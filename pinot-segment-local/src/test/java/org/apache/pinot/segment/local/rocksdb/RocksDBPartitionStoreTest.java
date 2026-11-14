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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


public class RocksDBPartitionStoreTest {
  private File _tempDir;

  @BeforeMethod
  public void setUp()
      throws Exception {
    _tempDir = Files.createTempDirectory("rocksdb-store-test").toFile();
  }

  @AfterMethod
  public void tearDown() {
    FileUtils.deleteQuietly(_tempDir);
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  @Test
  public void testColumnFamiliesAreIndependent() {
    File dir = new File(_tempDir, "p0");
    try (RocksDBPartitionStore store = new RocksDBPartitionStore(dir, List.of("default", "previous"),
        RocksDBMetadataStoreConfig.defaults())) {
      store.put(0, bytes("k"), bytes("v0"));
      store.put(1, bytes("k"), bytes("v1"));
      assertEquals(store.get(0, bytes("k")), bytes("v0"));
      assertEquals(store.get(1, bytes("k")), bytes("v1"));
      store.delete(0, bytes("k"));
      assertNull(store.get(0, bytes("k")));
      assertEquals(store.get(1, bytes("k")), bytes("v1"));
    }
  }

  @Test
  public void testOpenWipesLeftoversAndCloseDeletesDirectory()
      throws Exception {
    File dir = new File(_tempDir, "p0");
    FileUtils.forceMkdir(dir);
    File leftover = new File(dir, "leftover");
    FileUtils.touch(leftover);
    RocksDBPartitionStore store =
        new RocksDBPartitionStore(dir, List.of("default"), RocksDBMetadataStoreConfig.defaults());
    assertFalse(leftover.exists());
    store.put(0, bytes("k"), bytes("v"));
    store.close();
    assertFalse(dir.exists());
    assertTrue(store.isClosed());
    // Idempotent close, and operations after close fail fast instead of touching freed native memory.
    store.close();
    assertThrows(IllegalStateException.class, () -> store.get(0, bytes("k")));
  }

  @Test
  public void testSharedEnvironmentIsReferenceCounted() {
    RocksDBPartitionStore first =
        new RocksDBPartitionStore(new File(_tempDir, "a"), List.of("default"), RocksDBMetadataStoreConfig.defaults());
    RocksDBPartitionStore second =
        new RocksDBPartitionStore(new File(_tempDir, "b"), List.of("default"), RocksDBMetadataStoreConfig.defaults());
    assertTrue(first.getEnvironment() == second.getEnvironment());
    assertEquals(RocksDBEnvironment.getRefCount(), 2);
    first.close();
    assertEquals(RocksDBEnvironment.getRefCount(), 1);
    second.close();
    assertEquals(RocksDBEnvironment.getRefCount(), 0);
  }

  @Test
  public void testIngestSorted() {
    try (RocksDBPartitionStore store = new RocksDBPartitionStore(new File(_tempDir, "p0"), List.of("default"),
        RocksDBMetadataStoreConfig.defaults())) {
      store.put(0, bytes("a"), bytes("old"));
      List<byte[]> keys = new ArrayList<>();
      List<byte[]> values = new ArrayList<>();
      for (int i = 0; i < 1000; i++) {
        keys.add(bytes(String.format("k%04d", i)));
        values.add(bytes("v" + i));
      }
      store.ingestSorted(0, keys, values);
      assertEquals(store.get(0, bytes("k0042")), bytes("v42"));
      assertEquals(store.get(0, bytes("a")), bytes("old"));
      int count = 0;
      try (RocksIterator iterator = store.newIterator(0)) {
        for (iterator.seekToFirst(); iterator.isValid(); iterator.next()) {
          count++;
        }
      }
      assertEquals(count, 1001);
      assertEquals(new File(_tempDir, "p0").listFiles((d, n) -> n.startsWith("ingest_")).length, 0);
    }
  }

  @Test
  public void testRetriesTransientErrorsAndWrapsPersistentOnes() {
    RocksDBMetadataStoreConfig config = RocksDBMetadataStoreConfig.from(null,
        Map.of("rocksdb.maxRetries", "2", "rocksdb.retryBackoffMs", "1"));
    try (RocksDBPartitionStore store = new RocksDBPartitionStore(new File(_tempDir, "retry"), List.of("default"),
        config)) {
      AtomicInteger attempts = new AtomicInteger();
      assertEquals(store.withRetry("op", () -> {
        if (attempts.incrementAndGet() < 3) {
          throw new RocksDBException("transient");
        }
        return "ok";
      }), "ok");
      assertEquals(store.getNumRetries(), 2);
      assertEquals(store.getNumFailures(), 0);

      RocksDBMetadataStoreException e = expectThrows(RocksDBMetadataStoreException.class,
          () -> store.withRetry("op", () -> {
            throw new RocksDBException("persistent");
          }));
      assertTrue(e.getMessage().contains("failed after 3 attempts"), e.getMessage());
      assertEquals(store.getNumFailures(), 1);
    }
  }

  @Test
  public void testCheckpointReopensWithTheSameKeys()
      throws Exception {
    File dir = new File(_tempDir, "p0");
    byte[] key = bytes("a");
    byte[] value = bytes("1");
    RocksDBRecoveryManifest manifest = new RocksDBRecoveryManifest("fp", 1.5, 1,
        Map.of("seg", new RocksDBRecoveryManifest.Segment(9L, 3, 1)));
    try (RocksDBPartitionStore store = new RocksDBPartitionStore(dir, List.of("default", "previous"),
        RocksDBMetadataStoreConfig.defaults())) {
      store.put(0, key, value);
      store.put(1, key, bytes("prev"));
      assertTrue(store.getLookupCount() >= 0);
      store.checkpoint(manifest);
    }
    assertFalse(dir.exists());
    File recovery = RocksDBPartitionStore.recoveryDir(dir);
    RocksDBRecoveryManifest written =
        RocksDBRecoveryManifest.read(new File(recovery, RocksDBRecoveryManifest.FILE_NAME));
    assertEquals(written.getNumPrimaryKeys(), 1);

    try (RocksDBPartitionStore reopened = new RocksDBPartitionStore(dir, List.of("default", "previous"),
        RocksDBMetadataStoreConfig.defaults())) {
      assertNull(reopened.get(0, key));
      RocksDBRecoveryManifest read = reopened.readRecoveryManifest();
      assertEquals(read.mismatch("fp", Map.of("seg", 9L)), null);
      assertEquals(read.mismatch("other", Map.of("seg", 9L)), "table key config changed");
      assertTrue(read.mismatch("fp", Map.of("seg", 8L)).contains("changed"));
      reopened.adoptRecovery();
      assertEquals(reopened.get(0, key), value);
      assertEquals(reopened.get(1, key), bytes("prev"));
      // The checkpoint stays, so a later restart can reopen it again.
      assertTrue(new File(recovery, "db").isDirectory());
    }
  }

  @Test
  public void testConfigFromInstanceAndTable() {
    PinotConfiguration instanceConfig = new PinotConfiguration(
        Map.of("rocksdb.blockCacheSizeBytes", "1000", "rocksdb.maxRetries", "5", "rocksdb.dataDir", "/data/rocks"));
    RocksDBMetadataStoreConfig config = RocksDBMetadataStoreConfig.from(instanceConfig,
        Map.of("rocksdb.maxRetries", "1", "rocksdb.ttlScanMaxKeysPerSecond", "500", "other", "x"));
    assertEquals(config.getBlockCacheSizeBytes(), 1000);
    assertEquals(config.getMaxRetries(), 1);
    assertEquals(config.getTtlScanMaxKeysPerSecond(), 500);
    assertEquals(config.resolveDataDir(new File("/ignored")), new File("/data/rocks"));
    assertEquals(RocksDBMetadataStoreConfig.defaults().resolveDataDir(new File("/srv")),
        new File("/srv", RocksDBMetadataStoreConfig.DEFAULT_DATA_DIR_NAME));
    assertThrows(IllegalArgumentException.class,
        () -> RocksDBMetadataStoreConfig.from(null, Map.of("rocksdb.maxRetries", "-1")));
    assertThrows(IllegalArgumentException.class,
        () -> RocksDBMetadataStoreConfig.from(null, Map.of("rocksdb.blockCacheSizeBytes", "lots")));
  }
}
