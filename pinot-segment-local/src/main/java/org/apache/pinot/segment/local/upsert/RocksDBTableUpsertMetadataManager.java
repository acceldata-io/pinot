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
import org.apache.pinot.common.utils.config.QueryOptionsUtils;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.utils.SegmentOperationsThrottlerSet;
import org.apache.pinot.segment.spi.IndexSegment;
import org.apache.pinot.segment.spi.SegmentContext;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.config.table.UpsertConfig;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.env.PinotConfiguration;


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
  private final Map<Integer, BasePartitionUpsertMetadataManager> _partitionMetadataManagerMap =
      new ConcurrentHashMap<>();
  private RocksDBMetadataStoreConfig _storeConfig;

  @Override
  public void init(PinotConfiguration instanceUpsertConfig, TableConfig tableConfig, Schema schema,
      TableDataManager tableDataManager, @Nullable SegmentOperationsThrottlerSet segmentOperationsThrottlerSet) {
    UpsertConfig upsertConfig = tableConfig.getUpsertConfig();
    Preconditions.checkArgument(upsertConfig != null, "Upsert must be enabled for table: %s",
        tableConfig.getTableName());
    _storeConfig = RocksDBMetadataStoreConfig.from(instanceUpsertConfig, upsertConfig.getMetadataManagerConfigs());
    super.init(instanceUpsertConfig, tableConfig, schema, tableDataManager, segmentOperationsThrottlerSet);
  }

  @Override
  public BasePartitionUpsertMetadataManager getOrCreatePartitionManager(int partitionId) {
    return _partitionMetadataManagerMap.computeIfAbsent(partitionId,
        k -> new RocksDBPartitionUpsertMetadataManager(_tableNameWithType, k, _context, _storeConfig));
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
