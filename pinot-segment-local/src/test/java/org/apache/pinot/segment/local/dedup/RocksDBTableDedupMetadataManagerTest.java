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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreException;
import org.apache.pinot.spi.config.table.DedupConfig;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.config.table.TableType;
import org.apache.pinot.spi.data.FieldSpec.DataType;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.builder.TableConfigBuilder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;


/// Selection between the RocksDB and in-memory dedup partition managers.
public class RocksDBTableDedupMetadataManagerTest {
  private static final Schema SCHEMA = new Schema.SchemaBuilder().setSchemaName("mytable")
      .addSingleValueDimension("myCol", DataType.STRING).setPrimaryKeyColumns(List.of("myCol")).build();

  private File _tempDir;

  @BeforeMethod
  public void setUp()
      throws IOException {
    _tempDir = Files.createTempDirectory("rocksdb-table-dedup-test").toFile();
  }

  @AfterMethod
  public void tearDown() {
    FileUtils.deleteQuietly(_tempDir);
  }

  private TableDedupMetadataManager create(PinotConfiguration instanceDedupConfig, Map<String, String> configs) {
    DedupConfig dedupConfig = new DedupConfig();
    dedupConfig.setMetadataManagerClass(RocksDBTableDedupMetadataManager.class.getName());
    Map<String, String> allConfigs = new HashMap<>(configs);
    allConfigs.putIfAbsent("rocksdb.dataDir", new File(_tempDir, "rocksdb").getAbsolutePath());
    dedupConfig.setMetadataManagerConfigs(allConfigs);
    TableConfig tableConfig =
        new TableConfigBuilder(TableType.REALTIME).setTableName("mytable").setDedupConfig(dedupConfig).build();
    TableDataManager tableDataManager = mock(TableDataManager.class);
    when(tableDataManager.getTableDataDir()).thenReturn(new File(_tempDir, "mytable_REALTIME"));
    return TableDedupMetadataManagerFactory.create(instanceDedupConfig, tableConfig, SCHEMA, tableDataManager, null);
  }

  private static void stopAndClose(TableDedupMetadataManager manager)
      throws IOException {
    manager.stop();
    manager.close();
  }

  @Test
  public void testSelection()
      throws IOException {
    TableDedupMetadataManager rocksdb = create(new PinotConfiguration(), Map.of());
    try {
      assertTrue(rocksdb instanceof RocksDBTableDedupMetadataManager);
      assertFalse(((RocksDBTableDedupMetadataManager) rocksdb).isInMemoryFallback());
      assertTrue(rocksdb.getOrCreatePartitionManager(0) instanceof RocksDBPartitionDedupMetadataManager);
      assertTrue(new File(_tempDir, "rocksdb/mytable_REALTIME/dedup_0").isDirectory());
    } finally {
      stopAndClose(rocksdb);
    }

    TableDedupMetadataManager disabled =
        create(new PinotConfiguration(Map.of("rocksdb.enabled", "false")), Map.of());
    try {
      assertTrue(((RocksDBTableDedupMetadataManager) disabled).isInMemoryFallback());
      assertTrue(disabled.getOrCreatePartitionManager(0) instanceof ConcurrentMapPartitionDedupMetadataManager);
    } finally {
      stopAndClose(disabled);
    }
  }

  @Test
  public void testOpenFailureFailsTableUnlessFallbackIsEnabled()
      throws IOException {
    File notADirectory = new File(_tempDir, "not-a-directory");
    FileUtils.touch(notADirectory);
    Map<String, String> brokenDataDir = Map.of("rocksdb.dataDir", notADirectory.getAbsolutePath());
    TableDedupMetadataManager noFallback = create(new PinotConfiguration(), brokenDataDir);
    try {
      assertThrows(RocksDBMetadataStoreException.class, () -> noFallback.getOrCreatePartitionManager(0));
    } finally {
      stopAndClose(noFallback);
    }

    Map<String, String> withFallbackConfigs = new HashMap<>(brokenDataDir);
    withFallbackConfigs.put("rocksdb.fallbackToInMemoryOnInitFailure", "true");
    TableDedupMetadataManager withFallback = create(new PinotConfiguration(), withFallbackConfigs);
    try {
      assertTrue(withFallback.getOrCreatePartitionManager(0) instanceof ConcurrentMapPartitionDedupMetadataManager);
      assertTrue(((RocksDBTableDedupMetadataManager) withFallback).isInMemoryFallback());
    } finally {
      stopAndClose(withFallback);
    }
  }
}
