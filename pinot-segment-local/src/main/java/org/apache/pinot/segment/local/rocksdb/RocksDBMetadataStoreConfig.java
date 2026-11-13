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

import com.google.common.base.Preconditions;
import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;
import org.apache.pinot.spi.env.PinotConfiguration;


/**
 * Settings for the RocksDB-backed upsert and dedup metadata stores.
 *
 * <p>Values are read from the server instance config under {@code pinot.server.instance.upsert.rocksdb.*} (or
 * {@code pinot.server.instance.dedup.rocksdb.*}) and can be overridden per table through
 * {@code upsertConfig.metadataManagerConfigs} (or {@code dedupConfig.metadataManagerConfigs}) using the same keys with
 * the {@code rocksdb.} prefix, e.g. {@code "rocksdb.ttlScanMaxKeysPerSecond": "2000000"}.
 *
 * <p>Settings marked as server-wide are only honored by the first table that creates the shared
 * {@link RocksDBEnvironment}; later tables log a warning when they ask for different values.
 *
 * <p>Instances are immutable and thread-safe.
 */
public final class RocksDBMetadataStoreConfig {
  public static final String PREFIX = "rocksdb.";

  /// Root directory of all stores on this server. Defaults to {@code <server data dir>/rocksdb_metadata}.
  public static final String DATA_DIR = "dataDir";
  /// Server-wide: shared LRU block cache size. Memtables are charged to the same cache.
  public static final String BLOCK_CACHE_SIZE_BYTES = "blockCacheSizeBytes";
  /// Server-wide: total memtable budget across all stores, charged to the block cache.
  public static final String WRITE_BUFFER_MANAGER_BYTES = "writeBufferManagerBytes";
  /// Server-wide: number of RocksDB flush and compaction threads.
  public static final String BACKGROUND_THREADS = "backgroundThreads";
  /// Per store: size of one memtable.
  public static final String WRITE_BUFFER_SIZE_BYTES = "writeBufferSizeBytes";
  /// Per store: bloom filter bits per key. 10 gives about a 1% false-positive rate.
  public static final String BLOOM_BITS_PER_KEY = "bloomBitsPerKey";
  /// Per store: data block size. Small blocks favour point lookups.
  public static final String BLOCK_SIZE_BYTES = "blockSizeBytes";
  /// Retries of a failed store operation before the operation fails.
  public static final String MAX_RETRIES = "maxRetries";
  /// Initial backoff between retries; doubles on every retry.
  public static final String RETRY_BACKOFF_MS = "retryBackoffMs";
  /// Server-wide: threads that run metadata TTL scans for all partitions.
  public static final String MAINTENANCE_THREADS = "maintenanceThreads";
  /// Rate limit of the metadata TTL scan, in keys per second. 0 means unlimited.
  public static final String TTL_SCAN_MAX_KEYS_PER_SECOND = "ttlScanMaxKeysPerSecond";
  /// Run the metadata TTL scan on the maintenance pool instead of the consuming thread. A full scan of a large store
  /// takes far longer than the in-memory map, and the consuming thread would not ingest while it runs.
  public static final String ASYNC_TTL_SCAN = "asyncTtlScan";
  /// Segments with at least this many valid keys are preloaded by ingesting a sorted SST file. 0 disables it.
  public static final String PRELOAD_SST_MIN_KEYS = "preloadSstMinKeys";
  /// Preload buffers at most this many keys of a segment on the heap before writing them to the store.
  public static final String PRELOAD_BATCH_KEYS = "preloadBatchKeys";
  /// How long a validDocIds snapshot waits for the lock of a segment that is being committed or replaced. Replacing a
  /// segment takes longer on RocksDB, so a non-blocking attempt usually misses the segment just committed, and a missed
  /// segment blocks first snapshots of all others. 0 keeps the non-blocking attempt of the in-memory managers.
  public static final String SNAPSHOT_SEGMENT_LOCK_WAIT_MS = "snapshotSegmentLockWaitMs";
  /// Use the in-memory manager if a partition store cannot be opened. Off by default: a table sized for RocksDB can
  /// exhaust the heap, so an open failure fails the table on that server instead.
  public static final String FALLBACK_TO_IN_MEMORY_ON_INIT_FAILURE = "fallbackToInMemoryOnInitFailure";
  /// Kill switch: {@code false} at server or table level makes the RocksDB managers use the in-memory map.
  public static final String ENABLED = "enabled";

  public static final String DEFAULT_DATA_DIR_NAME = "rocksdb_metadata";
  public static final long DEFAULT_BLOCK_CACHE_SIZE_BYTES = 1L << 30;
  public static final long DEFAULT_WRITE_BUFFER_MANAGER_BYTES = 256L << 20;
  public static final int DEFAULT_BACKGROUND_THREADS = 4;
  public static final long DEFAULT_WRITE_BUFFER_SIZE_BYTES = 64L << 20;
  public static final double DEFAULT_BLOOM_BITS_PER_KEY = 10;
  public static final long DEFAULT_BLOCK_SIZE_BYTES = 4L << 10;
  public static final int DEFAULT_MAX_RETRIES = 3;
  public static final long DEFAULT_RETRY_BACKOFF_MS = 100;
  public static final int DEFAULT_MAINTENANCE_THREADS = 2;
  public static final long DEFAULT_TTL_SCAN_MAX_KEYS_PER_SECOND = 0;
  public static final int DEFAULT_PRELOAD_SST_MIN_KEYS = 100_000;
  public static final int DEFAULT_PRELOAD_BATCH_KEYS = 500_000;
  public static final long DEFAULT_SNAPSHOT_SEGMENT_LOCK_WAIT_MS = 10_000;

  @Nullable
  private final String _dataDir;
  private final long _blockCacheSizeBytes;
  private final long _writeBufferManagerBytes;
  private final int _backgroundThreads;
  private final long _writeBufferSizeBytes;
  private final double _bloomBitsPerKey;
  private final long _blockSizeBytes;
  private final int _maxRetries;
  private final long _retryBackoffMs;
  private final int _maintenanceThreads;
  private final long _ttlScanMaxKeysPerSecond;
  private final boolean _asyncTtlScan;
  private final int _preloadSstMinKeys;
  private final int _preloadBatchKeys;
  private final long _snapshotSegmentLockWaitMs;
  private final boolean _fallbackToInMemoryOnInitFailure;
  private final boolean _enabled;

  private RocksDBMetadataStoreConfig(Map<String, String> values) {
    _dataDir = values.get(normalize(DATA_DIR));
    _blockCacheSizeBytes = getLong(values, BLOCK_CACHE_SIZE_BYTES, DEFAULT_BLOCK_CACHE_SIZE_BYTES, 1);
    _writeBufferManagerBytes = getLong(values, WRITE_BUFFER_MANAGER_BYTES, DEFAULT_WRITE_BUFFER_MANAGER_BYTES, 1);
    _backgroundThreads = (int) getLong(values, BACKGROUND_THREADS, DEFAULT_BACKGROUND_THREADS, 1);
    _writeBufferSizeBytes = getLong(values, WRITE_BUFFER_SIZE_BYTES, DEFAULT_WRITE_BUFFER_SIZE_BYTES, 1 << 20);
    _bloomBitsPerKey = Double.parseDouble(
        values.getOrDefault(normalize(BLOOM_BITS_PER_KEY), Double.toString(DEFAULT_BLOOM_BITS_PER_KEY)));
    Preconditions.checkArgument(_bloomBitsPerKey >= 0, "%s must be non-negative", BLOOM_BITS_PER_KEY);
    _blockSizeBytes = getLong(values, BLOCK_SIZE_BYTES, DEFAULT_BLOCK_SIZE_BYTES, 1 << 10);
    _maxRetries = (int) getLong(values, MAX_RETRIES, DEFAULT_MAX_RETRIES, 0);
    _retryBackoffMs = getLong(values, RETRY_BACKOFF_MS, DEFAULT_RETRY_BACKOFF_MS, 0);
    _maintenanceThreads = (int) getLong(values, MAINTENANCE_THREADS, DEFAULT_MAINTENANCE_THREADS, 1);
    _asyncTtlScan = Boolean.parseBoolean(values.getOrDefault(normalize(ASYNC_TTL_SCAN), "true"));
    _ttlScanMaxKeysPerSecond = getLong(values, TTL_SCAN_MAX_KEYS_PER_SECOND, DEFAULT_TTL_SCAN_MAX_KEYS_PER_SECOND, 0);
    _preloadSstMinKeys = (int) getLong(values, PRELOAD_SST_MIN_KEYS, DEFAULT_PRELOAD_SST_MIN_KEYS, 0);
    _preloadBatchKeys = (int) getLong(values, PRELOAD_BATCH_KEYS, DEFAULT_PRELOAD_BATCH_KEYS, 1);
    _snapshotSegmentLockWaitMs =
        getLong(values, SNAPSHOT_SEGMENT_LOCK_WAIT_MS, DEFAULT_SNAPSHOT_SEGMENT_LOCK_WAIT_MS, 0);
    _fallbackToInMemoryOnInitFailure =
        Boolean.parseBoolean(values.get(normalize(FALLBACK_TO_IN_MEMORY_ON_INIT_FAILURE)));
    _enabled = Boolean.parseBoolean(values.getOrDefault(normalize(ENABLED), "true"));
  }

  /// Matches the key normalization of {@link PinotConfiguration}, so instance and table keys compare equal.
  private static String normalize(String key) {
    return key.replace("-", "").replace("_", "").toLowerCase(Locale.ROOT);
  }

  /**
   * Builds the effective config from the instance-level config (already scoped to {@code upsert} or {@code dedup})
   * and the table-level {@code metadataManagerConfigs}. Table-level values win.
   */
  public static RocksDBMetadataStoreConfig from(@Nullable PinotConfiguration instanceConfig,
      @Nullable Map<String, String> tableConfigs) {
    Map<String, String> values = new HashMap<>();
    if (instanceConfig != null) {
      PinotConfiguration subset = instanceConfig.subset(PREFIX.substring(0, PREFIX.length() - 1));
      for (String key : subset.getKeys()) {
        values.put(normalize(key), subset.getProperty(key));
      }
    }
    if (tableConfigs != null) {
      for (Map.Entry<String, String> entry : tableConfigs.entrySet()) {
        if (entry.getKey().startsWith(PREFIX)) {
          values.put(normalize(entry.getKey().substring(PREFIX.length())), entry.getValue());
        }
      }
    }
    return new RocksDBMetadataStoreConfig(values);
  }

  private static final Set<String> SERVER_ONLY_KEYS =
      normalizeAll(BLOCK_CACHE_SIZE_BYTES, WRITE_BUFFER_MANAGER_BYTES, BACKGROUND_THREADS, MAINTENANCE_THREADS);
  private static final Set<String> BOOLEAN_KEYS =
      normalizeAll(ASYNC_TTL_SCAN, FALLBACK_TO_IN_MEMORY_ON_INIT_FAILURE, ENABLED);
  private static final Set<String> TABLE_KEYS =
      normalizeAll(DATA_DIR, WRITE_BUFFER_SIZE_BYTES, BLOOM_BITS_PER_KEY, BLOCK_SIZE_BYTES, MAX_RETRIES,
          RETRY_BACKOFF_MS, TTL_SCAN_MAX_KEYS_PER_SECOND, ASYNC_TTL_SCAN, PRELOAD_SST_MIN_KEYS, PRELOAD_BATCH_KEYS,
          SNAPSHOT_SEGMENT_LOCK_WAIT_MS, FALLBACK_TO_IN_MEMORY_ON_INIT_FAILURE, ENABLED);

  private static Set<String> normalizeAll(String... keys) {
    Set<String> normalized = new HashSet<>();
    for (String key : keys) {
      normalized.add(normalize(key));
    }
    return Set.copyOf(normalized);
  }

  /**
   * Validates the {@code rocksdb.*} entries of a table's {@code metadataManagerConfigs}, for the controller to reject
   * a bad table config up front. Unknown keys, server-wide keys, non-boolean flags, a relative data dir and bad
   * numbers are rejected.
   *
   * @throws IllegalArgumentException describing the first invalid entry
   */
  public static void validateTableConfigs(@Nullable Map<String, String> tableConfigs) {
    if (tableConfigs == null) {
      return;
    }
    for (Map.Entry<String, String> entry : tableConfigs.entrySet()) {
      String fullKey = entry.getKey();
      if (!fullKey.startsWith(PREFIX)) {
        continue;
      }
      String key = normalize(fullKey.substring(PREFIX.length()));
      String value = entry.getValue();
      Preconditions.checkArgument(!SERVER_ONLY_KEYS.contains(key),
          "RocksDB config: %s is server-wide and cannot be set per table; set it in the server config under "
              + "pinot.server.instance.upsert.%s or pinot.server.instance.dedup.%s", fullKey, fullKey, fullKey);
      Preconditions.checkArgument(TABLE_KEYS.contains(key), "Unknown RocksDB config: %s", fullKey);
      Preconditions.checkArgument(value != null && !value.trim().isEmpty(), "RocksDB config: %s has no value",
          fullKey);
      if (BOOLEAN_KEYS.contains(key)) {
        Preconditions.checkArgument("true".equalsIgnoreCase(value.trim()) || "false".equalsIgnoreCase(value.trim()),
            "RocksDB config: %s must be true or false, got: %s", fullKey, value);
      }
      if (key.equals(normalize(DATA_DIR))) {
        Preconditions.checkArgument(new File(value).isAbsolute(),
            "RocksDB config: %s must be an absolute path, got: %s", fullKey, value);
      }
    }
    // Parses and range-checks the numeric values
    from(null, tableConfigs);
  }

  public static RocksDBMetadataStoreConfig defaults() {
    return new RocksDBMetadataStoreConfig(Map.of());
  }

  private static long getLong(Map<String, String> values, String key, long defaultValue, long minValue) {
    String value = values.get(normalize(key));
    if (value == null) {
      return defaultValue;
    }
    long parsed;
    try {
      parsed = Long.parseLong(value.trim());
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(String.format("Invalid value: %s for RocksDB config: %s", value, key), e);
    }
    Preconditions.checkArgument(parsed >= minValue, "RocksDB config: %s must be >= %s, got: %s", key, minValue,
        parsed);
    return parsed;
  }

  /// Resolves the root directory of all stores, using {@code defaultParentDir} when {@link #DATA_DIR} is not set.
  public File resolveDataDir(File defaultParentDir) {
    return _dataDir != null ? new File(_dataDir) : new File(defaultParentDir, DEFAULT_DATA_DIR_NAME);
  }

  public long getBlockCacheSizeBytes() {
    return _blockCacheSizeBytes;
  }

  public long getWriteBufferManagerBytes() {
    return _writeBufferManagerBytes;
  }

  public int getBackgroundThreads() {
    return _backgroundThreads;
  }

  public long getWriteBufferSizeBytes() {
    return _writeBufferSizeBytes;
  }

  public double getBloomBitsPerKey() {
    return _bloomBitsPerKey;
  }

  public long getBlockSizeBytes() {
    return _blockSizeBytes;
  }

  public int getMaxRetries() {
    return _maxRetries;
  }

  public long getRetryBackoffMs() {
    return _retryBackoffMs;
  }

  public int getMaintenanceThreads() {
    return _maintenanceThreads;
  }

  public boolean isAsyncTtlScan() {
    return _asyncTtlScan;
  }

  public long getTtlScanMaxKeysPerSecond() {
    return _ttlScanMaxKeysPerSecond;
  }

  public int getPreloadBatchKeys() {
    return _preloadBatchKeys;
  }

  public int getPreloadSstMinKeys() {
    return _preloadSstMinKeys;
  }

  public long getSnapshotSegmentLockWaitMs() {
    return _snapshotSegmentLockWaitMs;
  }

  public boolean isFallbackToInMemoryOnInitFailure() {
    return _fallbackToInMemoryOnInitFailure;
  }

  public boolean isEnabled() {
    return _enabled;
  }
}
