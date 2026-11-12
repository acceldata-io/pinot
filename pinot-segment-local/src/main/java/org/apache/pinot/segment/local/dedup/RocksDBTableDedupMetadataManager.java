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

import com.google.common.base.Preconditions;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.utils.SegmentOperationsThrottlerSet;
import org.apache.pinot.spi.config.table.DedupConfig;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * {@link TableDedupMetadataManager} that keeps each partition's primary-key map in RocksDB
 * (see {@link RocksDBPartitionDedupMetadataManager}).
 *
 * <p>Enable it per table with {@code "metadataManagerClass":
 * "org.apache.pinot.segment.local.dedup.RocksDBTableDedupMetadataManager"} in the dedup config. Store settings are
 * described in {@link RocksDBMetadataStoreConfig}; {@code rocksdb.enabled=false} uses the in-memory map, and a store
 * that fails to open fails the table on this server unless {@code rocksdb.fallbackToInMemoryOnInitFailure} is set.
 * Thread-safe.
 */
@ThreadSafe
public class RocksDBTableDedupMetadataManager extends BaseTableDedupMetadataManager {
  private static final Logger LOGGER = LoggerFactory.getLogger(RocksDBTableDedupMetadataManager.class);

  private RocksDBMetadataStoreConfig _storeConfig;
  @Nullable
  private volatile String _inMemoryReason;

  @Override
  public void init(PinotConfiguration instanceDedupConfig, TableConfig tableConfig, Schema schema,
      TableDataManager tableDataManager, @Nullable SegmentOperationsThrottlerSet segmentOperationsThrottlerSet) {
    DedupConfig dedupConfig = tableConfig.getDedupConfig();
    Preconditions.checkArgument(dedupConfig != null, "Dedup must be enabled for table: %s",
        tableConfig.getTableName());
    _storeConfig = RocksDBMetadataStoreConfig.from(instanceDedupConfig, dedupConfig.getMetadataManagerConfigs());
    super.init(instanceDedupConfig, tableConfig, schema, tableDataManager, segmentOperationsThrottlerSet);
    if (!_storeConfig.isEnabled()) {
      _inMemoryReason = "RocksDB is disabled by config";
      LOGGER.warn("Using in-memory dedup metadata for table: {} because {}", _tableNameWithType, _inMemoryReason);
    }
  }

  @Override
  protected PartitionDedupMetadataManager createPartitionDedupMetadataManager(Integer partitionId) {
    if (_inMemoryReason == null) {
      try {
        return new RocksDBPartitionDedupMetadataManager(_tableNameWithType, partitionId, _context, _storeConfig);
      } catch (RuntimeException | LinkageError e) {
        if (!_storeConfig.isFallbackToInMemoryOnInitFailure()) {
          throw e;
        }
        LOGGER.error("Failed to open RocksDB dedup metadata for table: {}, partition: {}, using in-memory map",
            _tableNameWithType, partitionId, e);
        _inMemoryReason = "RocksDB failed to open: " + e;
      }
    }
    return new ConcurrentMapPartitionDedupMetadataManager(_tableNameWithType, partitionId, _context);
  }

  /// Returns true if this table keeps (some of) its partition maps in memory instead of RocksDB.
  public boolean isInMemoryFallback() {
    return _inMemoryReason != null;
  }
}
