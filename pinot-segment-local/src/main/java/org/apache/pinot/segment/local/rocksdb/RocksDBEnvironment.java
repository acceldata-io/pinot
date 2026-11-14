/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pinot.segment.local.rocksdb;

import com.google.common.annotations.VisibleForTesting;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.ToLongFunction;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.pinot.common.metrics.ServerGauge;
import org.apache.pinot.common.metrics.ServerMetrics;
import org.rocksdb.Cache;
import org.rocksdb.Env;
import org.rocksdb.LRUCache;
import org.rocksdb.Priority;
import org.rocksdb.RocksDB;
import org.rocksdb.Statistics;
import org.rocksdb.TickerType;
import org.rocksdb.WriteBufferManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Server-wide RocksDB resources shared by all metadata stores: the native library, one LRU block cache, one
 * {@link WriteBufferManager} that charges memtables to that cache, the RocksDB background thread pool, and a small
 * Java pool for maintenance scans. Sharing them bounds
 * the native memory of all stores together by {@link RocksDBMetadataStoreConfig#getBlockCacheSizeBytes()}, no matter
 * how many table partitions a server hosts.
 *
 * <p>The environment is reference counted. {@link #acquire} creates it on first use and {@link #release()} frees the
 * native resources when the last store is closed. Thread-safe.
 */
@ThreadSafe
public final class RocksDBEnvironment {
  private static final Logger LOGGER = LoggerFactory.getLogger(RocksDBEnvironment.class);

  private static final Object LOCK = new Object();
  @GuardedBy("LOCK")
  private static RocksDBEnvironment _instance;

  private final RocksDBMetadataStoreConfig _config;
  private final Cache _blockCache;
  private final WriteBufferManager _writeBufferManager;
  private final Statistics _statistics = new Statistics();
  private final ExecutorService _maintenanceExecutor;
  @GuardedBy("LOCK")
  private int _refCount;

  private RocksDBEnvironment(RocksDBMetadataStoreConfig config) {
    _config = config;
    _blockCache = new LRUCache(config.getBlockCacheSizeBytes());
    _writeBufferManager = new WriteBufferManager(config.getWriteBufferManagerBytes(), _blockCache);
    Env env = Env.getDefault();
    env.setBackgroundThreads(config.getBackgroundThreads(), Priority.LOW);
    env.setBackgroundThreads(Math.max(1, config.getBackgroundThreads() / 4), Priority.HIGH);
    AtomicInteger threadCounter = new AtomicInteger();
    _maintenanceExecutor = Executors.newFixedThreadPool(config.getMaintenanceThreads(), runnable -> {
      Thread thread = new Thread(runnable, "rocksdb-metadata-maintenance-" + threadCounter.getAndIncrement());
      thread.setDaemon(true);
      return thread;
    });
  }

  /**
   * Returns the shared environment and increments its reference count. The server-wide settings of {@code config}
   * only apply when this call creates the environment.
   */
  public static RocksDBEnvironment acquire(RocksDBMetadataStoreConfig config) {
    synchronized (LOCK) {
      if (_instance == null) {
        RocksDB.loadLibrary();
        _instance = new RocksDBEnvironment(config);
        registerGlobalGauges();
        LOGGER.info("Created RocksDB environment with block cache: {} bytes, write buffer manager: {} bytes, "
                + "background threads: {}", config.getBlockCacheSizeBytes(), config.getWriteBufferManagerBytes(),
            config.getBackgroundThreads());
      } else if (_instance._config.getBlockCacheSizeBytes() != config.getBlockCacheSizeBytes()
          || _instance._config.getWriteBufferManagerBytes() != config.getWriteBufferManagerBytes()) {
        LOGGER.warn("RocksDB environment already exists with block cache: {} bytes and write buffer manager: {} bytes; "
                + "ignoring the requested {} and {} bytes", _instance._config.getBlockCacheSizeBytes(),
            _instance._config.getWriteBufferManagerBytes(), config.getBlockCacheSizeBytes(),
            config.getWriteBufferManagerBytes());
      }
      _instance._refCount++;
      return _instance;
    }
  }

  /// Decrements the reference count and frees the native resources when it reaches zero.
  private static void registerGlobalGauges() {
    ServerMetrics serverMetrics = ServerMetrics.get();
    serverMetrics.setOrUpdateGlobalGauge(ServerGauge.ROCKSDB_BLOCK_CACHE_USAGE_BYTES,
        () -> currentValue(RocksDBEnvironment::getBlockCacheUsageBytes));
    serverMetrics.setOrUpdateGlobalGauge(ServerGauge.ROCKSDB_BLOCK_CACHE_PINNED_USAGE_BYTES,
        () -> currentValue(RocksDBEnvironment::getBlockCachePinnedUsageBytes));
    serverMetrics.setOrUpdateGlobalGauge(ServerGauge.ROCKSDB_BLOCK_CACHE_CAPACITY_BYTES,
        () -> currentValue(environment -> environment._config.getBlockCacheSizeBytes()));
    serverMetrics.setOrUpdateGlobalGauge(ServerGauge.ROCKSDB_BLOCK_CACHE_HITS,
        () -> currentValue(RocksDBEnvironment::getBlockCacheHitCount));
    serverMetrics.setOrUpdateGlobalGauge(ServerGauge.ROCKSDB_BLOCK_CACHE_MISSES,
        () -> currentValue(RocksDBEnvironment::getBlockCacheMissCount));
    serverMetrics.setOrUpdateGlobalGauge(ServerGauge.ROCKSDB_BLOCK_CACHE_HIT_RATIO_PERMILLE, () -> {
      long hits = currentValue(RocksDBEnvironment::getBlockCacheHitCount);
      long misses = currentValue(RocksDBEnvironment::getBlockCacheMissCount);
      long total = hits + misses;
      // 1000 until the first lookup, so an empty server does not look like a cache failure.
      return total == 0 ? 1000 : hits * 1000 / total;
    });
  }

  private static long currentValue(ToLongFunction<RocksDBEnvironment> function) {
    synchronized (LOCK) {
      return _instance != null ? function.applyAsLong(_instance) : 0;
    }
  }

  public void release() {
    synchronized (LOCK) {
      if (--_refCount == 0) {
        _maintenanceExecutor.shutdownNow();
        _writeBufferManager.close();
        _blockCache.close();
        _statistics.close();
        if (_instance == this) {
          _instance = null;
        }
        LOGGER.info("Closed RocksDB environment");
      }
    }
  }

  public Cache getBlockCache() {
    return _blockCache;
  }

  /// Shared by every store, so block-cache hit and miss counts cover the whole server.
  public Statistics getStatistics() {
    return _statistics;
  }

  public long getBlockCacheHitCount() {
    return _statistics.getTickerCount(TickerType.BLOCK_CACHE_HIT);
  }

  public long getBlockCacheMissCount() {
    return _statistics.getTickerCount(TickerType.BLOCK_CACHE_MISS);
  }

  public WriteBufferManager getWriteBufferManager() {
    return _writeBufferManager;
  }

  /// Shared pool for long-running store maintenance, such as metadata TTL scans, off the ingestion threads.
  public ExecutorService getMaintenanceExecutor() {
    return _maintenanceExecutor;
  }

  /// Bytes held by the shared block cache, including memtables charged to it.
  public long getBlockCacheUsageBytes() {
    synchronized (LOCK) {
      return _refCount > 0 ? _blockCache.getUsage() : 0;
    }
  }

  public long getBlockCachePinnedUsageBytes() {
    synchronized (LOCK) {
      return _refCount > 0 ? _blockCache.getPinnedUsage() : 0;
    }
  }

  @VisibleForTesting
  static int getRefCount() {
    synchronized (LOCK) {
      return _instance != null ? _instance._refCount : 0;
    }
  }
}
