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

import java.util.List;
import java.util.function.LongSupplier;
import org.apache.pinot.common.metrics.ServerGauge;
import org.apache.pinot.common.metrics.ServerMetrics;


/**
 * Registers the per-partition gauges of a RocksDB metadata store. Gauges are callbacks read by the metrics reporter,
 * so they are removed before the store is closed. Server-wide block-cache gauges are registered by
 * {@link RocksDBEnvironment}. Stateless and thread-safe.
 */
public final class RocksDBMetadataMetrics {
  private static final List<ServerGauge> PARTITION_GAUGES =
      List.of(ServerGauge.ROCKSDB_METADATA_DISK_SIZE_BYTES, ServerGauge.ROCKSDB_METADATA_STORE_RETRIES,
          ServerGauge.ROCKSDB_METADATA_STORE_FAILURES, ServerGauge.ROCKSDB_METADATA_STALE_LOCATIONS,
          ServerGauge.ROCKSDB_METADATA_LOOKUP_COUNT, ServerGauge.ROCKSDB_METADATA_LOOKUP_TIME_NS,
          ServerGauge.ROCKSDB_METADATA_RECOVERED);

  private RocksDBMetadataMetrics() {
  }

  public static void registerPartitionGauges(ServerMetrics serverMetrics, String tableNameWithType, int partitionId,
      RocksDBPartitionStore store, LongSupplier numStaleLocations) {
    serverMetrics.setOrUpdatePartitionGauge(tableNameWithType, partitionId,
        ServerGauge.ROCKSDB_METADATA_DISK_SIZE_BYTES, store::getDiskSizeBytes);
    serverMetrics.setOrUpdatePartitionGauge(tableNameWithType, partitionId, ServerGauge.ROCKSDB_METADATA_STORE_RETRIES,
        store::getNumRetries);
    serverMetrics.setOrUpdatePartitionGauge(tableNameWithType, partitionId,
        ServerGauge.ROCKSDB_METADATA_STORE_FAILURES, store::getNumFailures);
    serverMetrics.setOrUpdatePartitionGauge(tableNameWithType, partitionId,
        ServerGauge.ROCKSDB_METADATA_STALE_LOCATIONS, numStaleLocations::getAsLong);
    serverMetrics.setOrUpdatePartitionGauge(tableNameWithType, partitionId, ServerGauge.ROCKSDB_METADATA_LOOKUP_COUNT,
        store::getLookupCount);
    serverMetrics.setOrUpdatePartitionGauge(tableNameWithType, partitionId,
        ServerGauge.ROCKSDB_METADATA_LOOKUP_TIME_NS, store::getAverageLookupTimeNs);
    serverMetrics.setValueOfPartitionGauge(tableNameWithType, partitionId, ServerGauge.ROCKSDB_METADATA_RECOVERED, 0);
  }

  public static void removePartitionGauges(ServerMetrics serverMetrics, String tableNameWithType, int partitionId) {
    for (ServerGauge gauge : PARTITION_GAUGES) {
      serverMetrics.removePartitionGauge(tableNameWithType, partitionId, gauge);
    }
  }

  public static void setInMemoryFallback(ServerMetrics serverMetrics, String tableNameWithType, boolean inMemory) {
    serverMetrics.setValueOfTableGauge(tableNameWithType, ServerGauge.ROCKSDB_METADATA_IN_MEMORY_FALLBACK,
        inMemory ? 1 : 0);
  }
}
