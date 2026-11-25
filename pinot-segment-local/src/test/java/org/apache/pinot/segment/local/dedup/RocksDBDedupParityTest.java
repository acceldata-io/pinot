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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.pinot.common.metrics.ServerMetrics;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.rocksdb.MetadataCodec;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.rocksdb.SegmentRegistry;
import org.apache.pinot.segment.spi.ImmutableSegment;
import org.apache.pinot.segment.spi.IndexSegment;
import org.apache.pinot.spi.config.table.HashFunction;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.data.readers.PrimaryKey;
import org.rocksdb.RocksIterator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;


/// Drives {@link ConcurrentMapPartitionDedupMetadataManager} and {@link RocksDBPartitionDedupMetadataManager} through
/// the same random sequence of preload, consume, commit, upload, remove and TTL steps and compares every duplicate
/// decision and the full key map after each step.
public class RocksDBDedupParityTest {
  private static final String REALTIME_TABLE_NAME = "testTable_REALTIME";
  private static final int NUM_KEYS = 300;

  private File _tempDir;

  @BeforeClass
  public void setUpClass() {
    ServerMetrics.register(mock(ServerMetrics.class));
  }

  @BeforeMethod
  public void setUp()
      throws IOException {
    _tempDir = Files.createTempDirectory("rocksdb-dedup-parity").toFile();
  }

  @AfterMethod
  public void tearDown() {
    FileUtils.deleteQuietly(_tempDir);
  }

  private static final class Row {
    final String _pk;
    final double _time;

    Row(String pk, double time) {
      _pk = pk;
      _time = time;
    }

    DedupRecordInfo toRecordInfo() {
      return new DedupRecordInfo(new PrimaryKey(new Object[]{_pk}), _time);
    }
  }

  private static String makeKey(int keyIndex) {
    StringBuilder key = new StringBuilder("txn-").append(String.format("%08d", keyIndex)).append('-');
    int length = 32 + Math.floorMod(keyIndex * 31, 17);
    Random keyRandom = new Random(keyIndex);
    while (key.length() < length) {
      key.append((char) ('a' + keyRandom.nextInt(26)));
    }
    return key.toString();
  }

  private static IndexSegment segment(String name, boolean immutable) {
    IndexSegment segment = immutable ? mock(ImmutableSegment.class) : mock(IndexSegment.class);
    when(segment.getSegmentName()).thenReturn(name);
    return segment;
  }

  @DataProvider
  public Object[][] cases() {
    List<Object[]> cases = new ArrayList<>();
    for (HashFunction hashFunction : new HashFunction[]{HashFunction.NONE, HashFunction.MURMUR3}) {
      for (double metadataTTL : new double[]{0, 25}) {
        for (long seed = 1; seed <= 3; seed++) {
          cases.add(new Object[]{hashFunction, metadataTTL, seed});
        }
      }
    }
    return cases.toArray(new Object[0][]);
  }

  @Test(dataProvider = "cases")
  public void testParity(HashFunction hashFunction, double metadataTTL, long seed)
      throws IOException {
    TableDataManager tableDataManager = mock(TableDataManager.class);
    when(tableDataManager.getTableDataDir()).thenReturn(new File(_tempDir, REALTIME_TABLE_NAME));
    DedupContext context = new DedupContext.Builder().setTableConfig(mock(TableConfig.class))
        .setSchema(mock(Schema.class)).setTableDataManager(tableDataManager).setPrimaryKeyColumns(List.of("pk"))
        .setHashFunction(hashFunction).setMetadataTTL(metadataTTL).setDedupTimeColumn(metadataTTL > 0 ? "t" : null)
        .build();
    RocksDBMetadataStoreConfig storeConfig = RocksDBMetadataStoreConfig.from(null,
        Map.of("rocksdb.dataDir", new File(_tempDir, "rocksdb").getAbsolutePath(), "rocksdb.asyncTtlScan", "false"));
    ConcurrentMapPartitionDedupMetadataManager expected =
        new ConcurrentMapPartitionDedupMetadataManager(REALTIME_TABLE_NAME, 0, context);
    RocksDBPartitionDedupMetadataManager actual =
        new RocksDBPartitionDedupMetadataManager(REALTIME_TABLE_NAME, 0, context, storeConfig);
    Random random = new Random(seed);
    Map<String, List<Row>> segments = new LinkedHashMap<>();
    Map<String, IndexSegment> expectedSegments = new HashMap<>();
    Map<String, IndexSegment> actualSegments = new HashMap<>();
    int numDuplicates = 0;
    try {
      // Preload a few segments, as after a restart
      int sequence = 0;
      for (; sequence < 3; sequence++) {
        String name = "preloaded_" + sequence;
        List<Row> rows = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
          rows.add(new Row(makeKey(random.nextInt(NUM_KEYS)), random.nextInt(20)));
        }
        segments.put(name, rows);
        IndexSegment expectedSegment = segment(name, true);
        IndexSegment actualSegment = segment(name, true);
        expectedSegments.put(name, expectedSegment);
        actualSegments.put(name, actualSegment);
        expected.doPreloadSegment((ImmutableSegment) expectedSegment, rows.stream().map(Row::toRecordInfo).iterator());
        actual.doPreloadSegment((ImmutableSegment) actualSegment, rows.stream().map(Row::toRecordInfo).iterator());
      }
      assertSameState(expected, actual, "preload");

      for (int step = 0; step < 300; step++) {
        int op = random.nextInt(10);
        String description;
        if (op < 6) {
          // Consume into a mutable segment, then commit it as an immutable one holding the non-duplicate rows
          String name = "consuming_" + sequence++;
          IndexSegment expectedMutable = segment(name, false);
          IndexSegment actualMutable = segment(name, false);
          List<Row> kept = new ArrayList<>();
          int numRows = 5 + random.nextInt(40);
          for (int i = 0; i < numRows; i++) {
            Row row = new Row(makeKey(random.nextInt(NUM_KEYS)), sequence + random.nextInt(20));
            boolean expectedPresent = expected.checkRecordPresentOrUpdate(row.toRecordInfo(), expectedMutable);
            boolean actualPresent = actual.checkRecordPresentOrUpdate(row.toRecordInfo(), actualMutable);
            assertEquals(actualPresent, expectedPresent, "Duplicate decision differs for " + row._pk);
            if (expectedPresent) {
              numDuplicates++;
            } else {
              kept.add(row);
            }
          }
          IndexSegment expectedCommitted = segment(name, true);
          IndexSegment actualCommitted = segment(name, true);
          expected.doAddOrReplaceSegment(expectedMutable, expectedCommitted,
              kept.stream().map(Row::toRecordInfo).iterator());
          actual.doAddOrReplaceSegment(actualMutable, actualCommitted, kept.stream().map(Row::toRecordInfo).iterator());
          actual._store.getSegmentRegistry().retire(actualMutable);
          segments.put(name, kept);
          expectedSegments.put(name, expectedCommitted);
          actualSegments.put(name, actualCommitted);
          description = "consume and commit " + name;
        } else if (op < 7) {
          String name = "uploaded_" + sequence++;
          List<Row> rows = new ArrayList<>();
          for (int i = 0; i < 5 + random.nextInt(40); i++) {
            rows.add(new Row(makeKey(random.nextInt(NUM_KEYS)), sequence + random.nextInt(20)));
          }
          IndexSegment expectedSegment = segment(name, true);
          IndexSegment actualSegment = segment(name, true);
          expected.doAddOrReplaceSegment(null, expectedSegment, rows.stream().map(Row::toRecordInfo).iterator());
          actual.doAddOrReplaceSegment(null, actualSegment, rows.stream().map(Row::toRecordInfo).iterator());
          segments.put(name, rows);
          expectedSegments.put(name, expectedSegment);
          actualSegments.put(name, actualSegment);
          description = "upload " + name;
        } else if (op < 9 && !segments.isEmpty()) {
          List<String> names = new ArrayList<>(segments.keySet());
          String name = names.get(random.nextInt(names.size()));
          List<Row> rows = segments.remove(name);
          expected.doRemoveSegment(expectedSegments.remove(name), rows.stream().map(Row::toRecordInfo).iterator());
          IndexSegment actualSegment = actualSegments.remove(name);
          actual.doRemoveSegment(actualSegment, rows.stream().map(Row::toRecordInfo).iterator());
          actual._store.getSegmentRegistry().retire(actualSegment);
          description = "remove " + name;
        } else {
          expected.removeExpiredPrimaryKeys();
          actual.removeExpiredPrimaryKeys();
          description = "TTL scan";
        }
        assertSameState(expected, actual, "step " + step + ": " + description);
      }
      assertTrue(numDuplicates > 50, "Too few duplicates: " + numDuplicates);
      assertRefCounts(actual);
    } finally {
      for (BasePartitionDedupMetadataManager manager : List.of(expected, actual)) {
        manager.stop();
        manager.close();
      }
    }
  }

  private static void assertSameState(ConcurrentMapPartitionDedupMetadataManager expected,
      RocksDBPartitionDedupMetadataManager actual, String step) {
    assertEquals(actual.getNumPrimaryKeys(), expected.getNumPrimaryKeys(), "Key count differs after: " + step);
    Map<String, String> expectedMap = new TreeMap<>();
    for (Map.Entry<Object, Pair<IndexSegment, Double>> entry : expected._primaryKeyToSegmentAndTimeMap.entrySet()) {
      expectedMap.put(hex(MetadataCodec.encodeKey(entry.getKey())),
          entry.getValue().getLeft().getSegmentName() + "@" + entry.getValue().getRight());
    }
    Map<String, String> actualMap = new TreeMap<>();
    try (RocksIterator iterator = actual._store.getPartitionStore().newIterator(0)) {
      for (iterator.seekToFirst(); iterator.isValid(); iterator.next()) {
        IndexSegment segment =
            actual._store.getSegmentRegistry().getSegment(MetadataCodec.decodeSegmentId(iterator.value()));
        actualMap.put(hex(iterator.key()),
            (segment != null ? segment.getSegmentName() : "?") + "@" + MetadataCodec.decodeDedupTime(iterator.value()));
      }
    }
    assertEquals(actualMap, expectedMap, "Key map differs after: " + step);
  }

  private static void assertRefCounts(RocksDBPartitionDedupMetadataManager actual) {
    Map<Integer, Long> storedRefs = new HashMap<>();
    try (RocksIterator iterator = actual._store.getPartitionStore().newIterator(0)) {
      for (iterator.seekToFirst(); iterator.isValid(); iterator.next()) {
        storedRefs.merge(MetadataCodec.decodeSegmentId(iterator.value()), 1L, Long::sum);
      }
    }
    SegmentRegistry registry = actual._store.getSegmentRegistry();
    storedRefs.forEach((id, count) -> assertEquals(registry.getRefCount(id), (long) count, "refCount of " + id));
    for (int retiredId : registry.getRetiredIds()) {
      assertTrue(storedRefs.containsKey(retiredId), "Unreferenced retired segment id: " + retiredId);
    }
  }

  private static String hex(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      builder.append(String.format("%02x", b));
    }
    return builder.toString();
  }
}
