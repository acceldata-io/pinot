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
package org.apache.pinot.segment.local.upsert;

import com.google.common.annotations.VisibleForTesting;
import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.pinot.common.metrics.ServerMeter;
import org.apache.pinot.segment.local.indexsegment.immutable.ImmutableSegmentImpl;
import org.apache.pinot.segment.local.rocksdb.MetadataCodec;
import org.apache.pinot.segment.local.rocksdb.PrimaryKeyLocationStore;
import org.apache.pinot.segment.local.rocksdb.PrimaryKeyLocationStore.Location;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.segment.readers.LazyRow;
import org.apache.pinot.segment.local.segment.readers.PrimaryKeyReader;
import org.apache.pinot.segment.local.utils.HashUtils;
import org.apache.pinot.segment.spi.ImmutableSegment;
import org.apache.pinot.segment.spi.IndexSegment;
import org.apache.pinot.segment.spi.MutableSegment;
import org.apache.pinot.segment.spi.index.mutable.ThreadSafeMutableRoaringBitmap;
import org.apache.pinot.spi.data.readers.GenericRow;
import org.apache.pinot.spi.data.readers.PrimaryKey;
import org.roaringbitmap.buffer.MutableRoaringBitmap;


/**
 * Implementation of {@link PartitionUpsertMetadataManager} that keeps the primary-key map in RocksDB instead of the
 * Java heap. Each record location costs a few dozen bytes on local disk and in the shared block cache, so a server can
 * track billions of keys within a bounded heap.
 *
 * <p>The logic mirrors {@link ConcurrentMapPartitionUpsertMetadataManager} line for line: every
 * {@code ConcurrentHashMap.compute} becomes {@link PrimaryKeyLocationStore#compute}, which holds a per-key stripe lock
 * around the RocksDB read-modify-write. Segments are referenced by small ids from a per-partition registry.
 *
 * <p>The store is rebuilt from segments (or from validDocIds snapshots with preload) on every start and deleted on
 * close; nothing in it is needed across restarts. Thread-safe.
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@ThreadSafe
public class RocksDBPartitionUpsertMetadataManager extends BasePartitionUpsertMetadataManager {
  public static final String STORE_DIR_PREFIX = "upsert_";

  // Used to initialize a reference to previous row for merging in partial upsert
  private final LazyRow _reusePreviousRow = new LazyRow();
  private final Map<String, Object> _reuseMergeResultHolder = new HashMap<>();

  @VisibleForTesting
  final PrimaryKeyLocationStore _store;
  private final RocksDBMetadataStoreConfig _storeConfig;

  public RocksDBPartitionUpsertMetadataManager(String tableNameWithType, int partitionId, UpsertContext context,
      RocksDBMetadataStoreConfig storeConfig) {
    super(tableNameWithType, partitionId, context);
    _storeConfig = storeConfig;
    _store = new PrimaryKeyLocationStore(getStoreDir(tableNameWithType, partitionId, context, storeConfig),
        storeConfig);
    _logger.info("Using RocksDB upsert metadata store in: {}", _store.getPartitionStore().getDir());
  }

  @VisibleForTesting
  static File getStoreDir(String tableNameWithType, int partitionId, UpsertContext context,
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
  protected long getNumPrimaryKeys() {
    return _store.getNumPrimaryKeys();
  }

  @Override
  protected void doAddOrReplaceSegment(ImmutableSegmentImpl segment, ThreadSafeMutableRoaringBitmap validDocIds,
      @Nullable ThreadSafeMutableRoaringBitmap queryableDocIds, Iterator<RecordInfo> recordInfoIterator,
      @Nullable IndexSegment oldSegment, @Nullable MutableRoaringBitmap validDocIdsForOldSegment) {
    String segmentName = segment.getSegmentName();
    segment.enableUpsert(this, validDocIds, queryableDocIds);

    AtomicInteger numKeysInWrongSegment = new AtomicInteger();
    while (recordInfoIterator.hasNext()) {
      RecordInfo recordInfo = recordInfoIterator.next();
      int newDocId = recordInfo.getDocId();
      Comparable newComparisonValue = recordInfo.getComparisonValue();
      _store.compute(toKey(recordInfo.getPrimaryKey()), (primaryKey, currentRecordLocation) -> {
        if (currentRecordLocation != null) {
          // Existing primary key
          IndexSegment currentSegment = currentRecordLocation.getSegment();
          int currentDocId = currentRecordLocation.getDocId();
          int comparisonResult = newComparisonValue.compareTo(currentRecordLocation.getComparisonValue());

          // The current record is in the same segment
          // Update the record location when there is a tie to keep the newer record. Note that the record info
          // iterator will return records with incremental doc ids.
          if (currentSegment == segment) {
            if (comparisonResult >= 0) {
              replaceDocId(segment, validDocIds, queryableDocIds, currentDocId, newDocId, recordInfo);
              return new Location(segment, newDocId, newComparisonValue);
            } else {
              return currentRecordLocation;
            }
          }

          // The current record is in an old segment being replaced
          // This could happen when committing a consuming segment, or reloading a completed segment. In this
          // case, we want to update the record location when there is a tie because the record locations should
          // point to the new added segment instead of the old segment being replaced. Also, do not update the valid
          // doc ids for the old segment because it has not been replaced yet. We pass in an optional valid doc ids
          // snapshot for the old segment, which can be updated and used to track the docs not replaced yet.
          if (currentSegment == oldSegment) {
            if (comparisonResult >= 0) {
              if (validDocIdsForOldSegment == null && oldSegment != null && oldSegment.getValidDocIds() != null) {
                // Update the old segment's bitmap in place if a copy of the bitmap was not provided.
                replaceDocId(segment, validDocIds, queryableDocIds, oldSegment, currentDocId, newDocId, recordInfo);
              } else {
                addDocId(segment, validDocIds, queryableDocIds, newDocId, recordInfo);
                if (validDocIdsForOldSegment != null) {
                  validDocIdsForOldSegment.remove(currentDocId);
                }
              }
              if (_context.isTableTypeInconsistentDuringConsumption() && currentSegment instanceof MutableSegment) {
                _store.removePrevious(primaryKey);
              }
              return new Location(segment, newDocId, newComparisonValue);
            } else {
              trackPreviousLocation(primaryKey, currentSegment, segment, newDocId, newComparisonValue);
              return currentRecordLocation;
            }
          }

          // This should not happen because the previously replaced segment should have all keys removed. We still
          // handle it here, and also track the number of keys not properly replaced previously.
          String currentSegmentName = currentSegment.getSegmentName();
          if (currentSegmentName.equals(segmentName)) {
            numKeysInWrongSegment.getAndIncrement();
            if (comparisonResult >= 0) {
              addDocId(segment, validDocIds, queryableDocIds, newDocId, recordInfo);
              if (_context.isTableTypeInconsistentDuringConsumption() && currentSegment instanceof MutableSegment) {
                _store.removePrevious(primaryKey);
              }
              return new Location(segment, newDocId, newComparisonValue);
            } else {
              trackPreviousLocation(primaryKey, currentSegment, segment, newDocId, newComparisonValue);
              return currentRecordLocation;
            }
          }

          // The current record is in a different segment
          // Update the record location when getting a newer comparison value, or the value is the same as the
          // current value, but the segment has a larger sequence number (the segment is newer than the current
          // segment).
          if (comparisonResult > 0 || (comparisonResult == 0 && shouldReplaceOnComparisonTie(segmentName,
              currentSegmentName, getAuthoritativeUpdateOrCreationTime(segment),
              getAuthoritativeUpdateOrCreationTime(currentSegment)))) {
            replaceDocId(segment, validDocIds, queryableDocIds, currentSegment, currentDocId, newDocId, recordInfo);
            if (_context.isTableTypeInconsistentDuringConsumption() && currentSegment instanceof MutableSegment) {
              _store.removePrevious(primaryKey);
            }
            return new Location(segment, newDocId, newComparisonValue);
          } else {
            trackPreviousLocation(primaryKey, currentSegment, segment, newDocId, newComparisonValue);
            return currentRecordLocation;
          }
        } else {
          // New primary key
          addDocId(segment, validDocIds, queryableDocIds, newDocId, recordInfo);
          return new Location(segment, newDocId, newComparisonValue);
        }
      });
    }
    int numKeys = numKeysInWrongSegment.get();
    if (numKeys > 0) {
      _logger.warn("Found {} primary keys in the wrong segment when adding segment: {}", numKeys, segmentName);
      _serverMetrics.addMeteredTableValue(_tableNameWithType, ServerMeter.UPSERT_KEYS_IN_WRONG_SEGMENT, numKeys);
    }
  }

  /// While a consuming segment owns a key, remembers the newest location of that key in the segment being added, so
  /// the key can be reverted to it if the consuming segment is dropped.
  private void trackPreviousLocation(byte[] primaryKey, IndexSegment currentSegment, IndexSegment segment,
      int newDocId, Comparable newComparisonValue) {
    if (!_context.isTableTypeInconsistentDuringConsumption() || !(currentSegment instanceof MutableSegment)) {
      return;
    }
    Location prevRecordLocation = _store.getPrevious(primaryKey);
    if (prevRecordLocation == null || newComparisonValue.compareTo(prevRecordLocation.getComparisonValue()) >= 0) {
      _store.putPrevious(primaryKey, new Location(segment, newDocId, newComparisonValue));
    }
  }

  @Override
  protected void addSegmentWithoutUpsert(ImmutableSegmentImpl segment, ThreadSafeMutableRoaringBitmap validDocIds,
      @Nullable ThreadSafeMutableRoaringBitmap queryableDocIds, Iterator<RecordInfo> recordInfoIterator) {
    segment.enableUpsert(this, validDocIds, queryableDocIds);
    while (recordInfoIterator.hasNext()) {
      RecordInfo recordInfo = recordInfoIterator.next();
      int newDocId = recordInfo.getDocId();
      Comparable newComparisonValue = recordInfo.getComparisonValue();
      addDocId(segment, validDocIds, queryableDocIds, newDocId, recordInfo);
      _store.put(toKey(recordInfo.getPrimaryKey()), new Location(segment, newDocId, newComparisonValue));
    }
  }

  @Override
  protected void removeSegment(IndexSegment segment, Iterator<PrimaryKey> primaryKeyIterator) {
    while (primaryKeyIterator.hasNext()) {
      PrimaryKey primaryKey = primaryKeyIterator.next();
      _store.computeIfPresent(toKey(primaryKey), (pk, recordLocation) -> {
        if (recordLocation.getSegment() == segment) {
          if (_context.isTableTypeInconsistentDuringConsumption() && segment instanceof MutableSegment) {
            _store.removePrevious(pk);
          }
          return null;
        }
        return recordLocation;
      });
    }
  }

  @Override
  protected void revertAndRemoveSegment(IndexSegment segment,
      Iterator<Map.Entry<Integer, PrimaryKey>> primaryKeyIterator) {
    throw new UnsupportedOperationException("Reverting a consuming segment is not supported yet");
  }

  @Override
  protected void removeSegment(IndexSegment segment, MutableRoaringBitmap validDocIds) {
    try (PrimaryKeyReader primaryKeyReader = new PrimaryKeyReader(segment, _primaryKeyColumns)) {
      if (shouldRevertMetadataOnInconsistency(segment)) {
        revertAndRemoveSegment(segment, UpsertUtils.getRecordIterator(primaryKeyReader, validDocIds));
      } else {
        removeSegment(segment, UpsertUtils.getPrimaryKeyIterator(primaryKeyReader, validDocIds));
      }
    } catch (Exception e) {
      throw new RuntimeException(
          String.format("Caught exception while removing segment: %s, table: %s, message: %s", segment.getSegmentName(),
              _tableNameWithType, e.getMessage()), e);
    }
  }

  @Override
  protected void doReplaceSegment(ImmutableSegment segment, IndexSegment oldSegment) {
    super.doReplaceSegment(segment, oldSegment);
    _store.getSegmentRegistry().retire(oldSegment);
  }

  @Override
  public void removeSegment(IndexSegment segment) {
    super.removeSegment(segment);
    _store.getSegmentRegistry().retire(segment);
  }

  @Override
  public void doRemoveExpiredPrimaryKeys() {
    throw new UnsupportedOperationException("Metadata TTL is not supported yet");
  }

  @Override
  protected int getPrevKeyToRecordLocationSize() {
    return _store.getNumPreviousKeys();
  }

  @Override
  protected void clearPrevKeyToRecordLocation() {
    _store.clearPrevious();
  }

  @Override
  protected boolean doAddRecord(MutableSegment segment, RecordInfo recordInfo) {
    AtomicBoolean isOutOfOrderRecord = new AtomicBoolean(false);
    ThreadSafeMutableRoaringBitmap validDocIds = Objects.requireNonNull(segment.getValidDocIds());
    ThreadSafeMutableRoaringBitmap queryableDocIds = segment.getQueryableDocIds();
    int newDocId = recordInfo.getDocId();
    Comparable newComparisonValue = recordInfo.getComparisonValue();

    // When TTL is enabled, update largestSeenComparisonValue when adding new record
    if (isTTLEnabled()) {
      double comparisonValue = ((Number) newComparisonValue).doubleValue();
      _largestSeenComparisonValue.getAndUpdate(v -> Math.max(v, comparisonValue));
    }
    _store.compute(toKey(recordInfo.getPrimaryKey()), (primaryKey, currentRecordLocation) -> {
      if (currentRecordLocation != null) {
        // Existing primary key
        IndexSegment currentSegment = currentRecordLocation.getSegment();
        // Update the record location when the new comparison value is greater than or equal to the current value.
        // Update the record location when there is a tie to keep the newer record.
        if (newComparisonValue.compareTo(currentRecordLocation.getComparisonValue()) >= 0) {
          int currentDocId = currentRecordLocation.getDocId();
          Location newRecordLocation = new Location(segment, newDocId, newComparisonValue);
          if (segment == currentSegment) {
            replaceDocId(segment, validDocIds, queryableDocIds, currentDocId, newDocId, recordInfo);
          } else {
            // For consistent ParallelSegmentConsumptionPolicy like DISALLOW_ALWAYS and ALLOW_DURING_BUILD_ONLY,
            // we shouldn't be seeing two mutable segments, so ideally current segment shouldn't point to
            // Mutable segment, unless other modes are enabled which could lead to inconsistent behaviour
            if (_context.isTableTypeInconsistentDuringConsumption() && !(currentSegment instanceof MutableSegment)) {
              _store.putPrevious(primaryKey, currentRecordLocation);
            }
            replaceDocId(segment, validDocIds, queryableDocIds, currentSegment, currentDocId, newDocId, recordInfo);
          }
          return newRecordLocation;
        } else {
          // Out-of-order record
          handleOutOfOrderEvent(currentRecordLocation.getComparisonValue(), recordInfo.getComparisonValue());
          isOutOfOrderRecord.set(true);
          return currentRecordLocation;
        }
      } else {
        // New primary key
        addDocId(segment, validDocIds, queryableDocIds, newDocId, recordInfo);
        return new Location(segment, newDocId, newComparisonValue);
      }
    });

    updatePrimaryKeyGauge();
    return !isOutOfOrderRecord.get();
  }

  /**
   * Merges the new record with the latest stored version of its key. Only the record location comes from RocksDB; the
   * previous row itself is read from its segment, as in the in-memory manager.
   */
  @Override
  protected GenericRow doUpdateRecord(GenericRow record, RecordInfo recordInfo) {
    assert _partialUpsertHandler != null;
    _store.computeIfPresent(toKey(recordInfo.getPrimaryKey()), (pk, recordLocation) -> {
      // Read the previous record if the following conditions are met:
      // - New record is not a DELETE record
      // - New record is not out-of-order
      // - Previous record is not deleted
      if (!recordInfo.isDeleteRecord()
          && recordInfo.getComparisonValue().compareTo(recordLocation.getComparisonValue()) >= 0) {
        IndexSegment currentSegment = recordLocation.getSegment();
        ThreadSafeMutableRoaringBitmap currentQueryableDocIds = currentSegment.getQueryableDocIds();
        int currentDocId = recordLocation.getDocId();
        if (currentQueryableDocIds == null || currentQueryableDocIds.contains(currentDocId)) {
          _reusePreviousRow.init(currentSegment, currentDocId);
          _partialUpsertHandler.merge(_reusePreviousRow, record, _reuseMergeResultHolder);
          _reuseMergeResultHolder.clear();
        }
      }
      return recordLocation;
    });
    return record;
  }

  @Override
  protected void doClose() {
    _store.close();
  }

  @VisibleForTesting
  RocksDBMetadataStoreConfig getStoreConfig() {
    return _storeConfig;
  }
}
