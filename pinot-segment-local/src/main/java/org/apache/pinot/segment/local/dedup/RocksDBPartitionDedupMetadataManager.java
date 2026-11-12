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
package org.apache.pinot.segment.local.dedup;

import com.google.common.annotations.VisibleForTesting;
import java.io.File;
import java.util.Iterator;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.pinot.segment.local.rocksdb.DedupKeyStore;
import org.apache.pinot.segment.local.rocksdb.DedupKeyStore.Entry;
import org.apache.pinot.segment.local.rocksdb.MetadataCodec;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataMetrics;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.utils.HashUtils;
import org.apache.pinot.segment.spi.ImmutableSegment;
import org.apache.pinot.segment.spi.IndexSegment;
import org.apache.pinot.spi.data.readers.PrimaryKey;


/**
 * Dedup metadata manager that keeps the partition's primary-key map in RocksDB on local disk instead of the Java heap.
 * The logic mirrors {@link ConcurrentMapPartitionDedupMetadataManager}. The store is rebuilt from the segments on
 * every start, like the in-memory map. The metadata TTL scan runs on the shared maintenance pool unless
 * {@code asyncTtlScan} is off. Thread-safe.
 */
@ThreadSafe
public class RocksDBPartitionDedupMetadataManager extends BasePartitionDedupMetadataManager {
  public static final String STORE_DIR_PREFIX = "dedup_";

  @VisibleForTesting
  final DedupKeyStore _store;
  private final RocksDBMetadataStoreConfig _storeConfig;
  private final AtomicBoolean _ttlScanRunning = new AtomicBoolean();

  public RocksDBPartitionDedupMetadataManager(String tableNameWithType, int partitionId, DedupContext dedupContext,
      RocksDBMetadataStoreConfig storeConfig) {
    super(tableNameWithType, partitionId, dedupContext);
    _storeConfig = storeConfig;
    _store = new DedupKeyStore(getStoreDir(tableNameWithType, partitionId, dedupContext, storeConfig), storeConfig);
    RocksDBMetadataMetrics.registerPartitionGauges(_serverMetrics, tableNameWithType, partitionId,
        _store.getPartitionStore(), _store::getNumStaleEntries);
    _logger.info("Using RocksDB dedup metadata store in: {}", _store.getPartitionStore().getDir());
  }

  static File getStoreDir(String tableNameWithType, int partitionId, DedupContext context,
      RocksDBMetadataStoreConfig storeConfig) {
    File tableIndexDir = context.getTableIndexDir();
    File defaultParent = tableIndexDir != null && tableIndexDir.getParentFile() != null
        ? tableIndexDir.getParentFile()
        : new File(System.getProperty("java.io.tmpdir"));
    return new File(new File(storeConfig.resolveDataDir(defaultParent), tableNameWithType),
        STORE_DIR_PREFIX + partitionId);
  }

  private byte[] toKey(PrimaryKey primaryKey) {
    return MetadataCodec.encodeKey(HashUtils.hashPrimaryKey(primaryKey, _hashFunction));
  }

  @Override
  protected void doPreloadSegment(ImmutableSegment segment, Iterator<DedupRecordInfo> dedupRecordInfoIterator) {
    while (dedupRecordInfoIterator.hasNext()) {
      DedupRecordInfo dedupRecordInfo = dedupRecordInfoIterator.next();
      _store.put(toKey(dedupRecordInfo.getPrimaryKey()), new Entry(segment, dedupRecordInfo.getDedupTime()));
    }
  }

  @Override
  protected void doAddOrReplaceSegment(@Nullable IndexSegment oldSegment, IndexSegment newSegment,
      Iterator<DedupRecordInfo> dedupRecordInfoIteratorOfNewSegment) {
    String segmentName = newSegment.getSegmentName();
    while (dedupRecordInfoIteratorOfNewSegment.hasNext()) {
      DedupRecordInfo dedupRecordInfo = dedupRecordInfoIteratorOfNewSegment.next();
      double dedupTime = dedupRecordInfo.getDedupTime();
      _store.compute(toKey(dedupRecordInfo.getPrimaryKey()), (primaryKey, segmentAndTime) -> {
        // Stale metadata is treated as not existing when checking for deduplicates.
        if (segmentAndTime == null || isOutOfMetadataTTL(segmentAndTime.getDedupTime())) {
          return new Entry(newSegment, dedupTime);
        }
        // when oldSegment is null, it means we are adding a new segment
        // when oldSegment is not null, it means we are replacing an existing segment
        if (oldSegment == null) {
          _logger.warn("When adding a new segment: record in segment: {} with primary key: {} and dedup "
                  + "time: {} already exists in segment: {} with dedup time: {}", segmentName,
              dedupRecordInfo.getPrimaryKey(), dedupTime, segmentAndTime.getSegment().getSegmentName(),
              segmentAndTime.getDedupTime());
        } else if (segmentAndTime.getSegment() != oldSegment) {
          _logger.warn("When replacing a segment: record in segment: {} with primary key: {} and dedup "
                  + "time: {} exists in segment: {} with dedup time: {} (but not the segment: {} to replace)",
              segmentName, dedupRecordInfo.getPrimaryKey(), dedupTime, segmentAndTime.getSegment().getSegmentName(),
              segmentAndTime.getDedupTime(), oldSegment.getSegmentName());
        }
        // When dedup time is the same, we always keep the latest segment
        // This will handle segment replacement case correctly - a typical case is when a mutable segment is
        // replaced by an immutable segment
        if (segmentAndTime.getDedupTime() <= dedupTime) {
          return new Entry(newSegment, dedupTime);
        }
        return segmentAndTime;
      });
    }
  }

  @Override
  public void replaceSegment(IndexSegment oldSegment, IndexSegment newSegment) {
    super.replaceSegment(oldSegment, newSegment);
    _store.getSegmentRegistry().retire(oldSegment);
  }

  @Override
  protected void doRemoveSegment(IndexSegment segment, Iterator<DedupRecordInfo> dedupRecordInfoIterator) {
    while (dedupRecordInfoIterator.hasNext()) {
      DedupRecordInfo dedupRecordInfo = dedupRecordInfoIterator.next();
      _store.computeIfPresent(toKey(dedupRecordInfo.getPrimaryKey()), (primaryKey, segmentAndTime) -> {
        // do not need to compare dedup time because we are removing the segment
        return segmentAndTime.getSegment() == segment ? null : segmentAndTime;
      });
    }
  }

  /// Also retires out-of-TTL segments, whose keys the base class leaves for the TTL scan.
  @Override
  public void removeSegment(IndexSegment segment) {
    super.removeSegment(segment);
    _store.getSegmentRegistry().retire(segment);
  }

  /**
   * Starts the TTL scan on the shared maintenance pool and returns, unless {@code asyncTtlScan} is off. At most one
   * scan runs per partition, and it holds a pending operation so that {@link #close()} waits for it.
   */
  @Override
  protected void doRemoveExpiredPrimaryKeys() {
    if (!_storeConfig.isAsyncTtlScan()) {
      removeExpiredPrimaryKeysNow();
      return;
    }
    if (!_ttlScanRunning.compareAndSet(false, true)) {
      _logger.info("Skip scheduling TTL scan because the previous scan is still running");
      return;
    }
    if (!startOperation()) {
      _ttlScanRunning.set(false);
      return;
    }
    try {
      _store.getPartitionStore().getEnvironment().getMaintenanceExecutor().execute(() -> {
        try {
          long startTimeMs = System.currentTimeMillis();
          removeExpiredPrimaryKeysNow();
          _logger.info("Finished TTL scan in {}ms", System.currentTimeMillis() - startTimeMs);
        } catch (Exception e) {
          _logger.error("Caught exception while removing expired primary keys", e);
        } finally {
          _ttlScanRunning.set(false);
          finishOperation();
        }
      });
    } catch (RejectedExecutionException e) {
      _ttlScanRunning.set(false);
      finishOperation();
      throw e;
    }
  }

  @VisibleForTesting
  void removeExpiredPrimaryKeysNow() {
    double smallestTimeToKeep = _largestSeenTime.get() - _metadataTTL;
    long numRemoved = _store.removeOlderThan(smallestTimeToKeep, _storeConfig.getTtlScanMaxKeysPerSecond());
    if (numRemoved > 0) {
      _logger.info("Deleted {} primary keys based on metadataTTL", numRemoved);
    }
    updatePrimaryKeyGauge();
  }

  @Override
  public boolean checkRecordPresentOrUpdate(DedupRecordInfo dedupRecordInfo, IndexSegment indexSegment) {
    if (!startOperation()) {
      _logger.info("Skip adding record to {} because metadata manager is already stopped",
          indexSegment.getSegmentName());
      return true;
    }
    try {
      if (_metadataTTL > 0) {
        _largestSeenTime.getAndUpdate(time -> Math.max(time, dedupRecordInfo.getDedupTime()));
      }
      AtomicBoolean present = new AtomicBoolean(false);
      _store.compute(toKey(dedupRecordInfo.getPrimaryKey()), (primaryKey, segmentAndTime) -> {
        // Stale metadata (out of TTL but not yet cleaned up) is treated as not existing.
        if (segmentAndTime == null || isOutOfMetadataTTL(segmentAndTime.getDedupTime())) {
          return new Entry(indexSegment, dedupRecordInfo.getDedupTime());
        }
        present.set(true);
        return segmentAndTime;
      });
      if (!present.get()) {
        updatePrimaryKeyGauge();
      }
      return present.get();
    } finally {
      finishOperation();
    }
  }

  @Override
  public long getNumPrimaryKeys() {
    return _store.getNumKeys();
  }

  @Override
  protected void doClose() {
    RocksDBMetadataMetrics.removePartitionGauges(_serverMetrics, _tableNameWithType, _partitionId);
    _store.close();
  }
}
