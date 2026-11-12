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

import com.google.common.base.Preconditions;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.pinot.common.metrics.ServerMetrics;
import org.apache.pinot.common.utils.config.QueryOptionsUtils;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataMetrics;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.utils.SegmentOperationsThrottlerSet;
import org.apache.pinot.segment.spi.IndexSegment;
import org.apache.pinot.segment.spi.SegmentContext;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.config.table.UpsertConfig;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * {@link TableUpsertMetadataManager} that keeps each partition's primary-key map in RocksDB
 * (see {@link RocksDBPartitionUpsertMetadataManager}).
 *
 * <p>Enable it per table with {@code "metadataManagerClass":
 * "org.apache.pinot.segment.local.upsert.RocksDBTableUpsertMetadataManager"} in the upsert config, or for all upsert
 * tables of a server with {@code pinot.server.instance.upsert.default.metadata.manager.class}. Store settings are
 * described in {@link RocksDBMetadataStoreConfig}. Thread-safe.
 */
@ThreadSafe
public class RocksDBTableUpsertMetadataManager extends BaseTableUpsertMetadataManager {
  private static final Logger LOGGER = LoggerFactory.getLogger(RocksDBTableUpsertMetadataManager.class);

  private final Map<Integer, BasePartitionUpsertMetadataManager> _partitionMetadataManagerMap =
      new ConcurrentHashMap<>();
  private RocksDBMetadataStoreConfig _storeConfig;
  /// Why this table uses the in-memory map, or null when it uses RocksDB.
  @Nullable
  private volatile String _inMemoryReason;

  @Override
  public void init(PinotConfiguration instanceUpsertConfig, TableConfig tableConfig, Schema schema,
      TableDataManager tableDataManager, @Nullable SegmentOperationsThrottlerSet segmentOperationsThrottlerSet) {
    UpsertConfig upsertConfig = tableConfig.getUpsertConfig();
    Preconditions.checkArgument(upsertConfig != null, "Upsert must be enabled for table: %s",
        tableConfig.getTableName());
    _storeConfig = RocksDBMetadataStoreConfig.from(instanceUpsertConfig, upsertConfig.getMetadataManagerConfigs());
    super.init(instanceUpsertConfig, tableConfig, schema, tableDataManager, segmentOperationsThrottlerSet);
    if (!_storeConfig.isEnabled()) {
      _inMemoryReason = "RocksDB is disabled by config";
    } else if (_context.isEnableDeletedKeysCompactionConsistency()) {
      _inMemoryReason = "enableDeletedKeysCompactionConsistency is not supported by RocksDB";
    }
    if (_inMemoryReason != null) {
      LOGGER.warn("Using in-memory upsert metadata for table: {} because {}", _tableNameWithType, _inMemoryReason);
    }
    RocksDBMetadataMetrics.setInMemoryFallback(ServerMetrics.get(), _tableNameWithType, _inMemoryReason != null);
  }

  /**
   * Opens the RocksDB partition manager. If the store cannot be opened, the exception fails the table on this server
   * unless {@code fallbackToInMemoryOnInitFailure} is set; other tables and replicas are unaffected.
   */
  @Override
  public BasePartitionUpsertMetadataManager getOrCreatePartitionManager(int partitionId) {
    return _partitionMetadataManagerMap.computeIfAbsent(partitionId, k -> {
      if (_inMemoryReason == null) {
        try {
          return new RocksDBPartitionUpsertMetadataManager(_tableNameWithType, k, _context, _storeConfig);
        } catch (RuntimeException | LinkageError e) {
          if (!_storeConfig.isFallbackToInMemoryOnInitFailure()) {
            throw e;
          }
          LOGGER.error("Failed to open RocksDB upsert metadata for table: {}, partition: {}, using in-memory map",
              _tableNameWithType, k, e);
          _inMemoryReason = "RocksDB failed to open: " + e;
          RocksDBMetadataMetrics.setInMemoryFallback(ServerMetrics.get(), _tableNameWithType, true);
        }
      }
      return newInMemoryPartitionManager(k);
    });
  }

  private BasePartitionUpsertMetadataManager newInMemoryPartitionManager(int partitionId) {
    return _context.isEnableDeletedKeysCompactionConsistency()
        ? new ConcurrentMapPartitionUpsertMetadataManagerForConsistentDeletes(_tableNameWithType, partitionId, _context)
        : new ConcurrentMapPartitionUpsertMetadataManager(_tableNameWithType, partitionId, _context);
  }

  /// Returns true if this table keeps (some of) its partition maps in memory instead of RocksDB.
  public boolean isInMemoryFallback() {
    return _inMemoryReason != null;
  }

  @Override
  public void stop() {
    for (BasePartitionUpsertMetadataManager metadataManager : _partitionMetadataManagerMap.values()) {
      metadataManager.stop();
    }
  }

  @Override
  public Map<Integer, Long> getPartitionToPrimaryKeyCount() {
    Map<Integer, Long> partitionToPrimaryKeyCount = new HashMap<>();
    _partitionMetadataManagerMap.forEach(
        (partitionID, upsertMetadataManager) -> partitionToPrimaryKeyCount.put(partitionID,
            upsertMetadataManager.getNumPrimaryKeys()));
    return partitionToPrimaryKeyCount;
  }

  @Override
  public void lockForSegmentContexts() {
    _partitionMetadataManagerMap.forEach(
        (partitionID, upsertMetadataManager) -> upsertMetadataManager.getUpsertViewManager().lockTrackedSegments());
  }

  @Override
  public void unlockForSegmentContexts() {
    _partitionMetadataManagerMap.forEach(
        (partitionID, upsertMetadataManager) -> upsertMetadataManager.getUpsertViewManager().unlockTrackedSegments());
  }

  @Override
  public Set<String> getNewlyAddedSegments() {
    Set<String> newlyAddedSegments = new HashSet<>();
    _partitionMetadataManagerMap.forEach((partitionID, upsertMetadataManager) -> newlyAddedSegments.addAll(
        upsertMetadataManager.getNewlyAddedSegments()));
    return newlyAddedSegments;
  }

  @Override
  public void setSegmentContexts(List<SegmentContext> segmentContexts, Map<String, String> queryOptions) {
    if (_context.getConsistencyMode() == UpsertConfig.ConsistencyMode.NONE || QueryOptionsUtils.isSkipUpsertView(
        queryOptions)) {
      for (SegmentContext segmentContext : segmentContexts) {
        IndexSegment segment = segmentContext.getIndexSegment();
        segmentContext.setQueryableDocIdsSnapshot(UpsertUtils.getQueryableDocIdsSnapshotFromSegment(segment));
      }
      return;
    }
    _partitionMetadataManagerMap.forEach(
        (partitionID, upsertMetadataManager) -> upsertMetadataManager.getUpsertViewManager()
            .setSegmentContexts(segmentContexts, queryOptions));
  }

  @Override
  public void close()
      throws IOException {
    for (BasePartitionUpsertMetadataManager metadataManager : _partitionMetadataManagerMap.values()) {
      metadataManager.close();
    }
  }
}
