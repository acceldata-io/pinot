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
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.helix.HelixManager;
import org.apache.pinot.common.metrics.ServerGauge;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.rocksdb.DedupKeyStore;
import org.apache.pinot.segment.local.rocksdb.DedupKeyStore.Entry;
import org.apache.pinot.segment.local.rocksdb.MetadataCodec;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataMetrics;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.rocksdb.RocksDBRecoveryManifest;
import org.apache.pinot.segment.local.segment.index.loader.IndexLoadingConfig;
import org.apache.pinot.segment.local.utils.HashUtils;
import org.apache.pinot.segment.local.utils.SegmentPreloadUtils;
import org.apache.pinot.segment.spi.ImmutableSegment;
import org.apache.pinot.segment.spi.IndexSegment;
import org.apache.pinot.spi.data.readers.PrimaryKey;


/**
 * Dedup metadata manager that keeps the partition's primary-key map in RocksDB on local disk instead of the Java heap.
 * The logic mirrors {@link ConcurrentMapPartitionDedupMetadataManager}. Ingestion writes are grouped by the store.
 * When {@code persistAcrossRestart} is on, a checkpoint is written after the sealed segments change and a restart
 * reopens it instead of reading every document, when those segments and their CRCs still match. The metadata TTL scan
 * runs on the shared maintenance pool unless {@code asyncTtlScan} is off. Thread-safe.
 */
@ThreadSafe
public class RocksDBPartitionDedupMetadataManager extends BasePartitionDedupMetadataManager {
  public static final String STORE_DIR_PREFIX = "dedup_";

  @VisibleForTesting
  final DedupKeyStore _store;
  private final RocksDBMetadataStoreConfig _storeConfig;
  private final AtomicBoolean _ttlScanRunning = new AtomicBoolean();
  private final Object _segmentSetLock = new Object();
  private final Map<String, Long> _onlineSegmentCrcs = new LinkedHashMap<>();
  private final Map<String, IndexSegment> _sealedSegments = new LinkedHashMap<>();
  private boolean _checkpointDirty;
  private boolean _checkpointRunning;
  private volatile boolean _checkpointingPreload;
  private volatile boolean _recoveredFromCheckpoint;
  private Map<String, RocksDBRecoveryManifest.Segment> _recoveredSegments = Map.of();

  public RocksDBPartitionDedupMetadataManager(String tableNameWithType, int partitionId, DedupContext dedupContext,
      RocksDBMetadataStoreConfig storeConfig) {
    super(tableNameWithType, partitionId, dedupContext);
    _storeConfig = storeConfig;
    _store = new DedupKeyStore(getStoreDir(tableNameWithType, partitionId, dedupContext, storeConfig), storeConfig);
    RocksDBMetadataMetrics.registerPartitionGauges(_serverMetrics, tableNameWithType, partitionId,
        _store.getPartitionStore(), _store::getNumStaleEntries);
    if (!storeConfig.isPersistAcrossRestart()) {
      _store.getPartitionStore().deleteRecovery();
    }
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
  protected void doPreloadSegments(TableDataManager tableDataManager, IndexLoadingConfig indexLoadingConfig,
      HelixManager helixManager, ExecutorService segmentPreloadExecutor)
      throws Exception {
    Map<String, Long> onlineSegmentCrcs =
        SegmentPreloadUtils.getOnlineSegmentCrcs(tableDataManager, _partitionId, helixManager, null);
    if (!tryRecover(onlineSegmentCrcs)) {
      _recoveredFromCheckpoint = false;
      if (_storeConfig.isPersistAcrossRestart()) {
        _store.getPartitionStore().deleteRecovery();
      }
    }
    _checkpointingPreload = true;
    try {
      super.doPreloadSegments(tableDataManager, indexLoadingConfig, helixManager, segmentPreloadExecutor);
    } finally {
      _checkpointingPreload = false;
    }
    checkpointIfSteady();
  }

  /**
   * Reopens the checkpoint when it covers exactly {@code onlineSegmentCrcs}. The segments are still loaded afterwards,
   * but their documents are not read.
   */
  @VisibleForTesting
  boolean tryRecover(Map<String, Long> onlineSegmentCrcs) {
    if (!_storeConfig.isPersistAcrossRestart()) {
      return false;
    }
    RocksDBRecoveryManifest manifest = _store.getPartitionStore().readRecoveryManifest();
    if (manifest == null) {
      return false;
    }
    String mismatch = manifest.mismatch(recoveryFingerprint(), onlineSegmentCrcs);
    if (mismatch != null) {
      _logger.info("RocksDB checkpoint not used ({}), rebuilding from segments", mismatch);
      return false;
    }
    try {
      _store.getPartitionStore().adoptRecovery();
    } catch (RuntimeException e) {
      _logger.warn("Failed to open the RocksDB checkpoint, rebuilding from segments", e);
      return false;
    }
    _store.restoreNumKeys(manifest.getNumPrimaryKeys());
    _largestSeenTime.set(manifest.getWatermark());
    _recoveredSegments = manifest.getSegments();
    _recoveredFromCheckpoint = true;
    updatePrimaryKeyGauge();
    _serverMetrics.setValueOfPartitionGauge(_tableNameWithType, _partitionId, ServerGauge.ROCKSDB_METADATA_RECOVERED,
        1);
    _logger.info("Recovered {} primary keys from the RocksDB checkpoint for {} dedup segments",
        manifest.getNumPrimaryKeys(), manifest.getSegments().size());
    return true;
  }

  @Override
  public void preloadSegment(ImmutableSegment segment) {
    super.preloadSegment(segment);
    trackSealed(segment);
  }

  @Override
  protected void doPreloadSegment(ImmutableSegment segment, Iterator<DedupRecordInfo> dedupRecordInfoIterator) {
    if (_recoveredFromCheckpoint) {
      bindRecovered(segment);
      _logger.info("Attaching recovered dedup segment: {}, current primary key count: {}", segment.getSegmentName(),
          getNumPrimaryKeys());
      return;
    }
    // Each put joins the store's write batch, so a rebuild does not pay a native write per document.
    while (dedupRecordInfoIterator.hasNext()) {
      DedupRecordInfo dedupRecordInfo = dedupRecordInfoIterator.next();
      _store.put(toKey(dedupRecordInfo.getPrimaryKey()), new Entry(segment, dedupRecordInfo.getDedupTime()));
    }
  }

  private void bindRecovered(ImmutableSegment segment) {
    RocksDBRecoveryManifest.Segment recovered = _recoveredSegments.get(segment.getSegmentName());
    if (recovered != null && recovered.getId() >= 0) {
      _store.getSegmentRegistry().bind(segment, recovered.getId(), recovered.getRefCount());
    }
  }

  @VisibleForTesting
  String recoveryFingerprint() {
    return _hashFunction + "|" + _primaryKeyColumns + "|" + _metadataTTL + "|" + _dedupTimeColumn;
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
  public void addSegment(IndexSegment segment) {
    super.addSegment(segment);
    trackSealed(segment);
    checkpointIfSteady();
  }

  @Override
  public void replaceSegment(IndexSegment oldSegment, IndexSegment newSegment) {
    super.replaceSegment(oldSegment, newSegment);
    _store.getSegmentRegistry().retire(oldSegment);
    untrack(oldSegment);
    trackSealed(newSegment);
    checkpointIfSteady();
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
    untrack(segment);
    checkpointIfSteady();
  }

  @VisibleForTesting
  void trackSealed(IndexSegment segment) {
    if (!(segment instanceof ImmutableSegment)) {
      return;
    }
    long crc;
    try {
      crc = Long.parseLong(segment.getSegmentMetadata().getCrc());
    } catch (RuntimeException e) {
      _logger.warn("Skip RocksDB checkpoint entry; segment {} has no numeric crc", segment.getSegmentName());
      return;
    }
    synchronized (_segmentSetLock) {
      _onlineSegmentCrcs.put(segment.getSegmentName(), crc);
      _sealedSegments.put(segment.getSegmentName(), segment);
    }
  }

  /// Drops {@code segment} from the checkpoint set. A committed segment keeps the consuming segment's name, and
  /// closing that consuming segment must not drop the committed one.
  @VisibleForTesting
  void untrack(IndexSegment segment) {
    synchronized (_segmentSetLock) {
      if (_sealedSegments.get(segment.getSegmentName()) != segment) {
        return;
      }
      _onlineSegmentCrcs.remove(segment.getSegmentName());
      _sealedSegments.remove(segment.getSegmentName());
    }
  }

  /// Checkpoints once the sealed-segment set stops changing. A checkpoint started earlier is not overwritten by a
  /// stale copy of the set.
  @VisibleForTesting
  void checkpointIfSteady() {
    if (_checkpointingPreload || !_storeConfig.isPersistAcrossRestart()) {
      return;
    }
    synchronized (_segmentSetLock) {
      _checkpointDirty = true;
      if (_checkpointRunning) {
        return;
      }
      _checkpointRunning = true;
    }
    try {
      while (true) {
        Map<String, Long> crcs;
        Map<String, IndexSegment> sealed;
        synchronized (_segmentSetLock) {
          _checkpointDirty = false;
          crcs = new LinkedHashMap<>(_onlineSegmentCrcs);
          sealed = new HashMap<>(_sealedSegments);
        }
        writeCheckpoint(crcs, sealed);
        synchronized (_segmentSetLock) {
          if (!_checkpointDirty) {
            _checkpointRunning = false;
            return;
          }
        }
      }
    } catch (RuntimeException e) {
      synchronized (_segmentSetLock) {
        _checkpointRunning = false;
        _checkpointDirty = true;
      }
      _logger.warn("Failed to checkpoint the RocksDB dedup metadata store; restart will rebuild from segments", e);
    }
  }

  private void writeCheckpoint(Map<String, Long> crcs, Map<String, IndexSegment> sealed) {
    Map<String, RocksDBRecoveryManifest.Segment> segments = new LinkedHashMap<>();
    for (Map.Entry<String, Long> entry : crcs.entrySet()) {
      IndexSegment segment = sealed.get(entry.getKey());
      int id = segment == null ? -1 : _store.getSegmentRegistry().getId(segment);
      long refCount = id >= 0 ? _store.getSegmentRegistry().getRefCount(id) : 0;
      segments.put(entry.getKey(), new RocksDBRecoveryManifest.Segment(entry.getValue(), id, refCount));
    }
    _store.getPartitionStore().checkpoint(new RocksDBRecoveryManifest(recoveryFingerprint(), _largestSeenTime.get(),
        getNumPrimaryKeys(), segments));
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
