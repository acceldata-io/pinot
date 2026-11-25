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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreException;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.config.table.TableType;
import org.apache.pinot.spi.config.table.UpsertConfig;
import org.apache.pinot.spi.data.FieldSpec.DataType;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.Enablement;
import org.apache.pinot.spi.utils.builder.TableConfigBuilder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;


/// Selection between the RocksDB and in-memory partition managers: factory wiring, kill switch, unsupported features,
/// and store open failures.
public class RocksDBTableUpsertMetadataManagerTest {
  private static final String RAW_TABLE_NAME = "testTable";
  private static final Schema SCHEMA = new Schema.SchemaBuilder()
      .setSchemaName(RAW_TABLE_NAME)
      .addSingleValueDimension("myCol", DataType.STRING)
      .addDateTimeField("timeCol", DataType.LONG, "TIMESTAMP", "1:MILLISECONDS")
      .setPrimaryKeyColumns(List.of("myCol"))
      .build();

  private File _tempDir;

  @BeforeMethod
  public void setUp()
      throws IOException {
    _tempDir = Files.createTempDirectory("rocksdb-table-upsert-test").toFile();
  }

  @AfterMethod
  public void tearDown() {
    FileUtils.deleteQuietly(_tempDir);
  }

  private UpsertConfig upsertConfig(Map<String, String> rocksdbConfigs) {
    UpsertConfig upsertConfig = new UpsertConfig(UpsertConfig.Mode.FULL);
    upsertConfig.setMetadataManagerClass(RocksDBTableUpsertMetadataManager.class.getName());
    Map<String, String> configs = new HashMap<>(rocksdbConfigs);
    configs.putIfAbsent("rocksdb.dataDir", new File(_tempDir, "rocksdb").getAbsolutePath());
    upsertConfig.setMetadataManagerConfigs(configs);
    return upsertConfig;
  }

  private TableUpsertMetadataManager create(PinotConfiguration instanceUpsertConfig, UpsertConfig upsertConfig) {
    TableConfig tableConfig = new TableConfigBuilder(TableType.REALTIME).setTableName(RAW_TABLE_NAME)
        .setTimeColumnName("timeCol").setUpsertConfig(upsertConfig).build();
    TableDataManager tableDataManager = mock(TableDataManager.class);
    when(tableDataManager.getTableDataDir()).thenReturn(new File(_tempDir, RAW_TABLE_NAME));
    return TableUpsertMetadataManagerFactory.create(instanceUpsertConfig, tableConfig, SCHEMA, tableDataManager, null);
  }

  private static void stopAndClose(TableUpsertMetadataManager manager)
      throws IOException {
    manager.stop();
    manager.close();
  }

  @Test
  public void testUsesRocksDBPerPartition()
      throws IOException {
    TableUpsertMetadataManager manager = create(new PinotConfiguration(), upsertConfig(Map.of()));
    try {
      assertTrue(manager instanceof RocksDBTableUpsertMetadataManager);
      assertFalse(((RocksDBTableUpsertMetadataManager) manager).isInMemoryFallback());
      assertTrue(manager.getOrCreatePartitionManager(0) instanceof RocksDBPartitionUpsertMetadataManager);
      assertTrue(manager.getOrCreatePartitionManager(1) instanceof RocksDBPartitionUpsertMetadataManager);
      assertTrue(new File(_tempDir, "rocksdb/" + RAW_TABLE_NAME + "_REALTIME/upsert_1").isDirectory());
    } finally {
      stopAndClose(manager);
    }
  }

  @Test
  public void testServerAndTableKillSwitch()
      throws IOException {
    PinotConfiguration instanceUpsertConfig = new PinotConfiguration(Map.of("rocksdb.enabled", "false"));
    TableUpsertMetadataManager serverDisabled = create(instanceUpsertConfig, upsertConfig(Map.of()));
    try {
      assertTrue(((RocksDBTableUpsertMetadataManager) serverDisabled).isInMemoryFallback());
      assertTrue(serverDisabled.getOrCreatePartitionManager(0) instanceof ConcurrentMapPartitionUpsertMetadataManager);
    } finally {
      stopAndClose(serverDisabled);
    }
    TableUpsertMetadataManager tableDisabled =
        create(new PinotConfiguration(), upsertConfig(Map.of("rocksdb.enabled", "false")));
    try {
      assertTrue(tableDisabled.getOrCreatePartitionManager(0) instanceof ConcurrentMapPartitionUpsertMetadataManager);
    } finally {
      stopAndClose(tableDisabled);
    }
  }

  @Test
  public void testDeletedKeysCompactionConsistencyUsesInMemory()
      throws IOException {
    UpsertConfig upsertConfig = upsertConfig(Map.of());
    upsertConfig.setEnableDeletedKeysCompactionConsistency(true);
    upsertConfig.setSnapshot(Enablement.ENABLE);
    upsertConfig.setDeletedKeysTTL(1000L);
    TableUpsertMetadataManager manager = create(new PinotConfiguration(), upsertConfig);
    try {
      assertTrue(((RocksDBTableUpsertMetadataManager) manager).isInMemoryFallback());
      assertTrue(manager.getOrCreatePartitionManager(0)
          instanceof ConcurrentMapPartitionUpsertMetadataManagerForConsistentDeletes);
    } finally {
      stopAndClose(manager);
    }
  }

  @Test
  public void testOpenFailureFailsTableUnlessFallbackIsEnabled()
      throws IOException {
    // A regular file where the store directory must be created makes every open fail
    File notADirectory = new File(_tempDir, "not-a-directory");
    FileUtils.touch(notADirectory);
    Map<String, String> brokenDataDir = Map.of("rocksdb.dataDir", notADirectory.getAbsolutePath());
    TableUpsertMetadataManager noFallback = create(new PinotConfiguration(), upsertConfig(brokenDataDir));
    try {
      assertThrows(RocksDBMetadataStoreException.class, () -> noFallback.getOrCreatePartitionManager(0));
    } finally {
      stopAndClose(noFallback);
    }

    Map<String, String> withFallbackConfigs = new HashMap<>(brokenDataDir);
    withFallbackConfigs.put("rocksdb.fallbackToInMemoryOnInitFailure", "true");
    TableUpsertMetadataManager withFallback = create(new PinotConfiguration(), upsertConfig(withFallbackConfigs));
    try {
      PartitionUpsertMetadataManager partitionManager = withFallback.getOrCreatePartitionManager(0);
      assertTrue(partitionManager instanceof ConcurrentMapPartitionUpsertMetadataManager);
      assertTrue(((RocksDBTableUpsertMetadataManager) withFallback).isInMemoryFallback());
      assertEquals(withFallback.getOrCreatePartitionManager(0), partitionManager);
    } finally {
      stopAndClose(withFallback);
    }
  }
}
