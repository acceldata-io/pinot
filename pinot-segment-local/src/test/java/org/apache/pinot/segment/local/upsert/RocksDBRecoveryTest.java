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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.rocksdb.RocksDBRecoveryManifest;
import org.apache.pinot.spi.config.table.HashFunction;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.data.Schema;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;


public class RocksDBRecoveryTest {
  private static final byte[] KEY = "k".getBytes(StandardCharsets.UTF_8);
  private static final byte[] VALUE = "v".getBytes(StandardCharsets.UTF_8);

  @Test
  public void testRestartReopensTheCheckpointWhenSegmentsMatch()
      throws Exception {
    File tempDir = Files.createTempDirectory("rocksdb-recovery").toFile();
    try {
      UpsertContext context = context(tempDir);
      RocksDBMetadataStoreConfig config = RocksDBMetadataStoreConfig.from(null,
          Map.of("rocksdb.dataDir", new File(tempDir, "data").getAbsolutePath()));
      RocksDBPartitionUpsertMetadataManager manager =
          new RocksDBPartitionUpsertMetadataManager("t_REALTIME", 0, context, config);
      manager._store.getPartitionStore().put(0, KEY, VALUE);
      manager._store.getPartitionStore().checkpoint(new RocksDBRecoveryManifest(manager.recoveryFingerprint(), 4.5, 1,
          Map.of("seg", new RocksDBRecoveryManifest.Segment(5L, 1, 1))));
      close(manager);

      RocksDBPartitionUpsertMetadataManager restarted =
          new RocksDBPartitionUpsertMetadataManager("t_REALTIME", 0, context, config);
      try {
        assertNull(restarted._store.getPartitionStore().get(0, KEY));
        assertTrue(restarted.tryRecover(Map.of("seg", 5L)));
        assertEquals(restarted._store.getPartitionStore().get(0, KEY), VALUE);
        assertEquals(restarted._store.getNumPrimaryKeys(), 1);
        assertEquals(restarted.getWatermark(), 4.5);
      } finally {
        close(restarted);
      }

      RocksDBPartitionUpsertMetadataManager mismatched =
          new RocksDBPartitionUpsertMetadataManager("t_REALTIME", 0, context, config);
      try {
        assertFalse(mismatched.tryRecover(Map.of("seg", 6L)));
        assertNull(mismatched._store.getPartitionStore().get(0, KEY));
      } finally {
        close(mismatched);
      }
    } finally {
      FileUtils.deleteDirectory(tempDir);
    }
  }

  private static UpsertContext context(File tempDir) {
    TableDataManager tableDataManager = mock(TableDataManager.class);
    when(tableDataManager.getTableDataDir()).thenReturn(new File(tempDir, "table"));
    return new UpsertContext.Builder().setTableConfig(mock(TableConfig.class)).setSchema(mock(Schema.class))
        .setTableDataManager(tableDataManager).setPrimaryKeyColumns(List.of("id"))
        .setComparisonColumns(List.of("ts")).setHashFunction(HashFunction.NONE).setEnableSnapshot(true)
        .build();
  }

  private static void close(RocksDBPartitionUpsertMetadataManager manager) {
    try {
      manager.stop();
      manager.close();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
