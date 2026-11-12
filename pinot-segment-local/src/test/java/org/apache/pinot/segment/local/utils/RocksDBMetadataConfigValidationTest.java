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
package org.apache.pinot.segment.local.utils;

import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.apache.pinot.segment.local.dedup.RocksDBTableDedupMetadataManager;
import org.apache.pinot.segment.local.upsert.RocksDBTableUpsertMetadataManager;
import org.apache.pinot.spi.config.table.DedupConfig;
import org.apache.pinot.spi.config.table.RoutingConfig;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.config.table.TableType;
import org.apache.pinot.spi.config.table.UpsertConfig;
import org.apache.pinot.spi.data.FieldSpec;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.utils.Enablement;
import org.apache.pinot.spi.utils.builder.TableConfigBuilder;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// Controller-side validation of tables that select a RocksDB upsert or dedup metadata manager.
public class RocksDBMetadataConfigValidationTest {
  private static final String TABLE_NAME = "testTable";
  private static final Schema SCHEMA = new Schema.SchemaBuilder().setSchemaName(TABLE_NAME)
      .addSingleValueDimension("myCol", FieldSpec.DataType.STRING).setPrimaryKeyColumns(List.of("myCol")).build();
  private static final Map<String, String> STREAM_CONFIGS =
      Map.of("streamType", "kafka", "stream.kafka.topic.name", "test", "stream.kafka.decoder.class.name",
          "org.apache.pinot.plugin.stream.kafka.KafkaJSONMessageDecoder");

  private static TableConfig upsertTable(@Nullable String managerClass, Map<String, String> configs) {
    UpsertConfig upsertConfig = new UpsertConfig(UpsertConfig.Mode.FULL);
    upsertConfig.setMetadataManagerClass(managerClass);
    upsertConfig.setMetadataManagerConfigs(configs);
    return table(upsertConfig, null);
  }

  private static TableConfig dedupTable(Map<String, String> configs) {
    DedupConfig dedupConfig = new DedupConfig();
    dedupConfig.setMetadataManagerClass(RocksDBTableDedupMetadataManager.class.getName());
    dedupConfig.setMetadataManagerConfigs(configs);
    return table(null, dedupConfig);
  }

  private static TableConfig table(@Nullable UpsertConfig upsertConfig, @Nullable DedupConfig dedupConfig) {
    return new TableConfigBuilder(TableType.REALTIME).setTableName(TABLE_NAME).setUpsertConfig(upsertConfig)
        .setDedupConfig(dedupConfig)
        .setRoutingConfig(
            new RoutingConfig(null, null, RoutingConfig.STRICT_REPLICA_GROUP_INSTANCE_SELECTOR_TYPE, false))
        .setStreamConfigs(STREAM_CONFIGS).build();
  }

  private static void assertRejected(TableConfig tableConfig, String expectedMessagePart) {
    IllegalStateException e = expectThrows(IllegalStateException.class,
        () -> TableConfigUtils.validateUpsertAndDedupConfig(tableConfig, SCHEMA));
    assertTrue(e.getMessage().contains(expectedMessagePart), e.getMessage());
  }

  @Test
  public void testValidConfigsAreAccepted() {
    String upsertClass = RocksDBTableUpsertMetadataManager.class.getName();
    TableConfigUtils.validateUpsertAndDedupConfig(upsertTable(upsertClass, Map.of()), SCHEMA);
    TableConfigUtils.validateUpsertAndDedupConfig(upsertTable(upsertClass,
        Map.of("rocksdb.dataDir", "/mnt/disk1/pinot/rocksdb", "rocksdb.ttlScanMaxKeysPerSecond", "200000",
            "rocksdb.bloomBitsPerKey", "12.5", "rocksdb.enabled", "TRUE", "rocksdb.preload_batch_keys", "100000",
            "otherManagerConfig", "kept")), SCHEMA);
    TableConfigUtils.validateUpsertAndDedupConfig(dedupTable(Map.of("rocksdb.asyncTtlScan", "false")), SCHEMA);
    // rocksdb.* keys are not checked when the in-memory manager is selected
    TableConfigUtils.validateUpsertAndDedupConfig(upsertTable(null, Map.of("rocksdb.unknown", "x")), SCHEMA);
  }

  @Test
  public void testInvalidConfigsAreRejected() {
    String upsertClass = RocksDBTableUpsertMetadataManager.class.getName();
    assertRejected(upsertTable(upsertClass, Map.of("rocksdb.ttlScanMaxKeyPerSecond", "1")),
        "Unknown RocksDB config: rocksdb.ttlScanMaxKeyPerSecond");
    assertRejected(upsertTable(upsertClass, Map.of("rocksdb.blockCacheSizeBytes", "1073741824")), "server-wide");
    assertRejected(upsertTable(upsertClass, Map.of("rocksdb.fallbackToInMemoryOnInitFailure", "yes")),
        "must be true or false");
    assertRejected(upsertTable(upsertClass, Map.of("rocksdb.dataDir", "relative/dir")), "absolute path");
    assertRejected(upsertTable(upsertClass, Map.of("rocksdb.maxRetries", "-1")), "must be >= 0");
    assertRejected(upsertTable(upsertClass, Map.of("rocksdb.writeBufferSizeBytes", "64MB")), "Invalid value");
    assertRejected(dedupTable(Map.of("rocksdb.maintenanceThreads", "4")), "server-wide");

    UpsertConfig consistentDeletes = new UpsertConfig(UpsertConfig.Mode.FULL);
    consistentDeletes.setMetadataManagerClass(upsertClass);
    consistentDeletes.setEnableDeletedKeysCompactionConsistency(true);
    consistentDeletes.setSnapshot(Enablement.ENABLE);
    consistentDeletes.setDeletedKeysTTL(100);
    assertRejected(table(consistentDeletes, null), "enableDeletedKeysCompactionConsistency is not supported");
  }
}
