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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.function.IntFunction;
import java.util.function.IntUnaryOperator;
import javax.annotation.Nullable;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.common.metrics.ServerMetrics;
import org.apache.pinot.common.utils.LLCSegmentName;
import org.apache.pinot.segment.local.data.manager.TableDataManager;
import org.apache.pinot.segment.local.indexsegment.immutable.ImmutableSegmentImpl;
import org.apache.pinot.segment.local.rocksdb.MetadataCodec;
import org.apache.pinot.segment.local.rocksdb.PrimaryKeyLocationStore;
import org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig;
import org.apache.pinot.segment.local.rocksdb.SegmentRegistry;
import org.apache.pinot.segment.local.segment.readers.LazyRow;
import org.apache.pinot.segment.spi.ColumnMetadata;
import org.apache.pinot.segment.spi.IndexSegment;
import org.apache.pinot.segment.spi.MutableSegment;
import org.apache.pinot.segment.spi.datasource.DataSource;
import org.apache.pinot.segment.spi.index.metadata.SegmentMetadataImpl;
import org.apache.pinot.segment.spi.index.mutable.ThreadSafeMutableRoaringBitmap;
import org.apache.pinot.segment.spi.index.reader.ForwardIndexReader;
import org.apache.pinot.spi.config.table.HashFunction;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.data.DimensionFieldSpec;
import org.apache.pinot.spi.data.FieldSpec.DataType;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.data.readers.GenericRow;
import org.apache.pinot.spi.data.readers.PrimaryKey;
import org.apache.pinot.spi.utils.ConsumingSegmentConsistencyModeListener;
import org.apache.pinot.spi.utils.builder.TableNameBuilder;
import org.roaringbitmap.buffer.MutableRoaringBitmap;
import org.rocksdb.RocksIterator;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;


/**
 * Parity harness: drives {@link ConcurrentMapPartitionUpsertMetadataManager} and
 * {@link RocksDBPartitionUpsertMetadataManager} with the same randomized sequence of consuming, committing,
 * uploading, reloading and removing segments, and asserts after every step that both produce the same validDocIds and
 * queryableDocIds for every segment and the same number of primary keys.
 *
 * <p>Keys are PhonePe-shaped: one string column of 32 to 48 characters. Comparison values come from a small range so
 * ties and out-of-order records are frequent.
 */
public class RocksDBUpsertParityTest {
  static final String RAW_TABLE_NAME = "parityTable";
  static final String REALTIME_TABLE_NAME = TableNameBuilder.REALTIME.tableNameWithType(RAW_TABLE_NAME);
  static final String PK_COLUMN = "pk";
  static final String COMPARISON_COLUMN = "updatedAt";
  static final String DELETE_COLUMN = "deleted";
  /// Column whose value names the row (segment name and doc id), so partial-upsert merges can be compared.
  static final String TAG_COLUMN = "tag";
  static final String MERGED_FROM = "mergedFrom";
  static final File TEMP_DIR = new File(FileUtils.getTempDirectory(), "RocksDBUpsertParityTest");

  @BeforeClass
  public void setUp()
      throws IOException {
    FileUtils.deleteQuietly(TEMP_DIR);
    FileUtils.forceMkdir(TEMP_DIR);
    ServerMetrics.register(mock(ServerMetrics.class));
  }

  @AfterClass
  public void tearDown() {
    FileUtils.deleteQuietly(TEMP_DIR);
  }

  /// One record of a generated segment.
  static final class Row {
    final String _pk;
    final int _comparisonValue;
    final boolean _deleted;

    Row(String pk, int comparisonValue, boolean deleted) {
      _pk = pk;
      _comparisonValue = comparisonValue;
      _deleted = deleted;
    }
  }

  /// A segment definition shared by both managers; each manager gets its own segment object and bitmaps.
  static final class SegmentSpec {
    final String _name;
    final long _creationTimeMs;
    final List<Row> _rows;

    SegmentSpec(String name, long creationTimeMs, List<Row> rows) {
      _name = name;
      _creationTimeMs = creationTimeMs;
      _rows = rows;
    }
  }

  /// A manager plus the segment objects it was given.
  static final class World {
    final BasePartitionUpsertMetadataManager _manager;
    final Map<String, IndexSegment> _segments = new LinkedHashMap<>();

    World(BasePartitionUpsertMetadataManager manager) {
      _manager = manager;
    }
  }

  static UpsertContext.Builder contextBuilder(HashFunction hashFunction, boolean withDeleteColumn) {
    TableDataManager tableDataManager = mock(TableDataManager.class);
    File tableDir = new File(TEMP_DIR, REALTIME_TABLE_NAME);
    when(tableDataManager.getTableDataDir()).thenReturn(tableDir);
    return new UpsertContext.Builder()
        .setTableConfig(mock(TableConfig.class))
        .setSchema(mock(Schema.class))
        .setTableDataManager(tableDataManager)
        .setPrimaryKeyColumns(List.of(PK_COLUMN))
        .setComparisonColumns(List.of(COMPARISON_COLUMN))
        .setHashFunction(hashFunction)
        .setDeleteRecordColumn(withDeleteColumn ? DELETE_COLUMN : null);
  }

  static RocksDBMetadataStoreConfig storeConfig() {
    return RocksDBMetadataStoreConfig.from(null,
        Map.of("rocksdb.dataDir", new File(TEMP_DIR, "rocksdb").getAbsolutePath(), "rocksdb.preloadSstMinKeys",
            "50", "rocksdb.asyncTtlScan", "false"));
  }

  static String makeKey(Random random, int keyIndex) {
    StringBuilder key = new StringBuilder("txn-").append(String.format("%08d", keyIndex)).append('-');
    // Deterministic length in [32, 48] per key.
    int length = 32 + Math.floorMod(keyIndex * 31, 17);
    Random keyRandom = new Random(keyIndex);
    while (key.length() < length) {
      key.append((char) ('a' + keyRandom.nextInt(26)));
    }
    return key.toString();
  }

  static List<Row> randomRows(Random random, int numRows, int numKeys, int minComparisonValue,
      int maxComparisonValue, boolean withDeletes) {
    List<Row> rows = new ArrayList<>(numRows);
    for (int i = 0; i < numRows; i++) {
      rows.add(new Row(makeKey(random, random.nextInt(numKeys)),
          minComparisonValue + random.nextInt(maxComparisonValue), withDeletes && random.nextInt(10) == 0));
    }
    return rows;
  }

  static Iterator<RecordInfo> recordInfos(List<Row> rows) {
    List<RecordInfo> recordInfos = new ArrayList<>(rows.size());
    for (int docId = 0; docId < rows.size(); docId++) {
      Row row = rows.get(docId);
      recordInfos.add(new RecordInfo(new PrimaryKey(new Object[]{row._pk}), docId, row._comparisonValue,
          row._deleted));
    }
    return recordInfos.iterator();
  }

  static RecordInfo recordInfo(List<Row> rows, int docId) {
    Row row = rows.get(docId);
    return new RecordInfo(new PrimaryKey(new Object[]{row._pk}), docId, row._comparisonValue, row._deleted);
  }

  private static DataSource stringDataSource(IntFunction<String> valueOfDoc) {
    DataSource dataSource = mock(DataSource.class);
    ForwardIndexReader forwardIndex = mock(ForwardIndexReader.class);
    when(forwardIndex.isSingleValue()).thenReturn(true);
    when(forwardIndex.getStoredType()).thenReturn(DataType.STRING);
    when(forwardIndex.getString(anyInt(), any())).thenAnswer(
        invocation -> valueOfDoc.apply(invocation.getArgument(0)));
    when(dataSource.getForwardIndex()).thenReturn(forwardIndex);
    return dataSource;
  }

  private static DataSource intDataSource(IntUnaryOperator valueOfDoc) {
    DataSource dataSource = mock(DataSource.class);
    ForwardIndexReader forwardIndex = mock(ForwardIndexReader.class);
    when(forwardIndex.isSingleValue()).thenReturn(true);
    when(forwardIndex.getStoredType()).thenReturn(DataType.INT);
    when(forwardIndex.getInt(anyInt(), any())).thenAnswer(
        invocation -> valueOfDoc.applyAsInt(invocation.getArgument(0)));
    when(dataSource.getForwardIndex()).thenReturn(forwardIndex);
    return dataSource;
  }

  static ImmutableSegmentImpl mockImmutableSegment(SegmentSpec spec, ThreadSafeMutableRoaringBitmap validDocIds,
      @Nullable ThreadSafeMutableRoaringBitmap queryableDocIds) {
    ImmutableSegmentImpl segment = mock(ImmutableSegmentImpl.class);
    when(segment.getSegmentName()).thenReturn(spec._name);
    when(segment.getValidDocIds()).thenReturn(validDocIds);
    when(segment.getQueryableDocIds()).thenReturn(queryableDocIds);
    DataSource pkDataSource = stringDataSource(docId -> spec._rows.get(docId)._pk);
    DataSource comparisonDataSource = intDataSource(docId -> spec._rows.get(docId)._comparisonValue);
    DataSource deleteDataSource = intDataSource(docId -> spec._rows.get(docId)._deleted ? 1 : 0);
    DataSource tagDataSource = stringDataSource(docId -> spec._name + "#" + docId);
    when(segment.getDataSource(anyString())).thenReturn(pkDataSource);
    when(segment.getDataSource(PK_COLUMN)).thenReturn(pkDataSource);
    when(segment.getDataSource(COMPARISON_COLUMN)).thenReturn(comparisonDataSource);
    when(segment.getDataSource(TAG_COLUMN)).thenReturn(tagDataSource);
    when(segment.getDataSource(DELETE_COLUMN)).thenReturn(deleteDataSource);
    SegmentMetadataImpl segmentMetadata = mock(SegmentMetadataImpl.class);
    when(segmentMetadata.getIndexCreationTime()).thenReturn(spec._creationTimeMs);
    when(segmentMetadata.getZkCreationTime()).thenReturn(spec._creationTimeMs);
    when(segmentMetadata.getTotalDocs()).thenReturn(spec._rows.size());
    TreeMap<String, ColumnMetadata> columnMetadataMap = new TreeMap<>();
    ColumnMetadata pkMetadata = mock(ColumnMetadata.class);
    when(pkMetadata.getFieldSpec()).thenReturn(new DimensionFieldSpec(PK_COLUMN, DataType.STRING, true));
    ColumnMetadata comparisonMetadata = mock(ColumnMetadata.class);
    when(comparisonMetadata.getFieldSpec()).thenReturn(new DimensionFieldSpec(COMPARISON_COLUMN, DataType.INT, true));
    int maxComparisonValue = spec._rows.stream().mapToInt(r -> r._comparisonValue).max().orElse(0);
    when(comparisonMetadata.getMaxValue()).thenReturn(maxComparisonValue);
    columnMetadataMap.put(PK_COLUMN, pkMetadata);
    columnMetadataMap.put(COMPARISON_COLUMN, comparisonMetadata);
    when(segmentMetadata.getColumnMetadataMap()).thenReturn(columnMetadataMap);
    when(segment.getSegmentMetadata()).thenReturn(segmentMetadata);
    return segment;
  }

  static MutableSegment mockMutableSegment(SegmentSpec spec, ThreadSafeMutableRoaringBitmap validDocIds,
      @Nullable ThreadSafeMutableRoaringBitmap queryableDocIds) {
    MutableSegment segment = mock(MutableSegment.class);
    when(segment.getSegmentName()).thenReturn(spec._name);
    when(segment.getValidDocIds()).thenReturn(validDocIds);
    when(segment.getQueryableDocIds()).thenReturn(queryableDocIds);
    DataSource pkDataSource = stringDataSource(docId -> spec._rows.get(docId)._pk);
    DataSource comparisonDataSource = intDataSource(docId -> spec._rows.get(docId)._comparisonValue);
    DataSource deleteDataSource = intDataSource(docId -> spec._rows.get(docId)._deleted ? 1 : 0);
    DataSource tagDataSource = stringDataSource(docId -> spec._name + "#" + docId);
    when(segment.getDataSource(anyString())).thenReturn(pkDataSource);
    when(segment.getDataSource(PK_COLUMN)).thenReturn(pkDataSource);
    when(segment.getDataSource(COMPARISON_COLUMN)).thenReturn(comparisonDataSource);
    when(segment.getDataSource(TAG_COLUMN)).thenReturn(tagDataSource);
    when(segment.getDataSource(DELETE_COLUMN)).thenReturn(deleteDataSource);
    SegmentMetadataImpl segmentMetadata = mock(SegmentMetadataImpl.class);
    when(segmentMetadata.getIndexCreationTime()).thenReturn(spec._creationTimeMs);
    when(segmentMetadata.getZkCreationTime()).thenReturn(spec._creationTimeMs);
    when(segment.getSegmentMetadata()).thenReturn(segmentMetadata);
    return segment;
  }

  static void assertSameState(World expected, World actual, String step) {
    assertEquals(actual._manager.getNumPrimaryKeys(), expected._manager.getNumPrimaryKeys(),
        "Primary key count differs after: " + step);
    assertEquals(actual._segments.keySet(), expected._segments.keySet(), "Segments differ after: " + step);
    for (Map.Entry<String, IndexSegment> entry : expected._segments.entrySet()) {
      IndexSegment expectedSegment = entry.getValue();
      IndexSegment actualSegment = actual._segments.get(entry.getKey());
      assertEquals(bitmap(actualSegment.getValidDocIds()), bitmap(expectedSegment.getValidDocIds()),
          "validDocIds of " + entry.getKey() + " differ after: " + step);
      assertEquals(bitmap(actualSegment.getQueryableDocIds()), bitmap(expectedSegment.getQueryableDocIds()),
          "queryableDocIds of " + entry.getKey() + " differ after: " + step);
    }
  }

  private static String bitmap(@Nullable ThreadSafeMutableRoaringBitmap bitmap) {
    return bitmap != null ? bitmap.getMutableRoaringBitmap().toString() : "null";
  }

  /**
   * Runs the randomized operation sequence against both worlds. {@code consumer} applies each step to one world.
   */
  static final class Driver {
    final Random _random;
    final boolean _withDeletes;
    final int _numKeys;
    final int _maxComparisonValue;
    final World _expected;
    final World _actual;
    int _sequenceNumber;
    @Nullable
    SegmentSpec _consuming;
    int _consumedRows;
    int _numMerges;
    /// Simulates replicas that diverged: commits may keep fewer rows than consumed, and consuming segments may be
    /// dropped. In PROTECTED mode both trigger reverting keys to their previous locations.
    boolean _divergent;
    /// Comparison values grow by this much per segment, so that metadata TTL expires old keys.
    int _comparisonDrift;
    boolean _ttlScans;
    /// Rows of each immutable segment, needed to preload them after a restart.
    final Map<String, SegmentSpec> _immutableSpecs = new LinkedHashMap<>();

    Driver(long seed, boolean withDeletes, int numKeys, int maxComparisonValue, World expected, World actual) {
      _random = new Random(seed);
      _withDeletes = withDeletes;
      _numKeys = numKeys;
      _maxComparisonValue = maxComparisonValue;
      _expected = expected;
      _actual = actual;
    }

    SegmentSpec newSpec(int numRows) {
      int sequenceNumber = _sequenceNumber++;
      String name = new LLCSegmentName(RAW_TABLE_NAME, 0, sequenceNumber, 1_700_000_000_000L).toString();
      return new SegmentSpec(name, 1_700_000_000_000L + sequenceNumber,
          randomRows(_random, numRows, _numKeys, sequenceNumber * _comparisonDrift, _maxComparisonValue,
              _withDeletes));
    }

    private ThreadSafeMutableRoaringBitmap newQueryable() {
      return _withDeletes ? new ThreadSafeMutableRoaringBitmap() : null;
    }

    void startConsuming() {
      _consuming = newSpec(10 + _random.nextInt(60));
      _consumedRows = 0;
      for (World world : List.of(_expected, _actual)) {
        world._segments.put(_consuming._name,
            mockMutableSegment(_consuming, new ThreadSafeMutableRoaringBitmap(), newQueryable()));
      }
    }

    void consume(int numRows) {
      int end = Math.min(_consuming._rows.size(), _consumedRows + numRows);
      for (int docId = _consumedRows; docId < end; docId++) {
        Object expectedMergedFrom = null;
        for (World world : List.of(_expected, _actual)) {
          MutableSegment segment = (MutableSegment) world._segments.get(_consuming._name);
          RecordInfo recordInfo = recordInfo(_consuming._rows, docId);
          GenericRow row = new GenericRow();
          row.putValue(PK_COLUMN, _consuming._rows.get(docId)._pk);
          row.putValue(COMPARISON_COLUMN, _consuming._rows.get(docId)._comparisonValue);
          Object mergedFrom = world._manager.updateRecord(row, recordInfo).getValue(MERGED_FROM);
          if (world == _expected) {
            expectedMergedFrom = mergedFrom;
          } else {
            assertEquals(mergedFrom, expectedMergedFrom,
                "Partial upsert merged a different previous row for doc " + docId + " of " + _consuming._name);
            if (mergedFrom != null) {
              _numMerges++;
            }
          }
          world._manager.addRecord(segment, recordInfo);
        }
      }
      _consumedRows = end;
    }

    void commit() {
      int numCommittedRows = _divergent && _consumedRows > 0 ? _random.nextInt(_consumedRows + 1) : _consumedRows;
      SegmentSpec committed = new SegmentSpec(_consuming._name, _consuming._creationTimeMs,
          new ArrayList<>(_consuming._rows.subList(0, numCommittedRows)));
      for (World world : List.of(_expected, _actual)) {
        IndexSegment oldSegment = world._segments.get(committed._name);
        ThreadSafeMutableRoaringBitmap validDocIds = new ThreadSafeMutableRoaringBitmap();
        ThreadSafeMutableRoaringBitmap queryableDocIds = newQueryable();
        ImmutableSegmentImpl segment = mockImmutableSegment(committed, validDocIds, queryableDocIds);
        world._manager.replaceSegment(segment, validDocIds, queryableDocIds, recordInfos(committed._rows), oldSegment);
        world._segments.put(committed._name, segment);
      }
      _immutableSpecs.put(committed._name, committed);
      _consuming = null;
    }

    void upload() {
      SegmentSpec spec = newSpec(5 + _random.nextInt(80));
      for (World world : List.of(_expected, _actual)) {
        ThreadSafeMutableRoaringBitmap validDocIds = new ThreadSafeMutableRoaringBitmap();
        ThreadSafeMutableRoaringBitmap queryableDocIds = newQueryable();
        ImmutableSegmentImpl segment = mockImmutableSegment(spec, validDocIds, queryableDocIds);
        world._manager.addSegment(segment, validDocIds, queryableDocIds, recordInfos(spec._rows));
        world._segments.put(spec._name, segment);
      }
      _immutableSpecs.put(spec._name, spec);
    }

    @Nullable
    String randomImmutable() {
      List<String> names = new ArrayList<>();
      for (Map.Entry<String, IndexSegment> entry : _expected._segments.entrySet()) {
        if (entry.getValue() instanceof ImmutableSegmentImpl) {
          names.add(entry.getKey());
        }
      }
      return names.isEmpty() ? null : names.get(_random.nextInt(names.size()));
    }

    void reload(String name, List<Row> rows) {
      SegmentSpec spec = null;
      for (World world : List.of(_expected, _actual)) {
        IndexSegment oldSegment = world._segments.get(name);
        if (spec == null) {
          spec = new SegmentSpec(name, oldSegment.getSegmentMetadata().getIndexCreationTime(), rows);
        }
        ThreadSafeMutableRoaringBitmap validDocIds = new ThreadSafeMutableRoaringBitmap();
        ThreadSafeMutableRoaringBitmap queryableDocIds = newQueryable();
        ImmutableSegmentImpl segment = mockImmutableSegment(spec, validDocIds, queryableDocIds);
        world._manager.replaceSegment(segment, validDocIds, queryableDocIds, recordInfos(rows), oldSegment);
        world._segments.put(name, segment);
      }
      _immutableSpecs.put(name, spec);
    }

    void remove(String name) {
      for (World world : List.of(_expected, _actual)) {
        // Segments added through the test hooks are not tracked, so call the removal logic directly.
        world._manager.doRemoveSegment(world._segments.remove(name));
        _immutableSpecs.remove(name);
      }
    }

    /// Runs {@code numSteps} random steps, checking parity after each.
    void run(int numSteps) {
      for (int step = 0; step < numSteps; step++) {
        String description;
        int choice = _random.nextInt(100);
        if (_consuming == null) {
          if (_ttlScans) {
            // Like RealtimeSegmentDataManager, remove expired keys before starting the next consuming segment.
            for (World world : List.of(_expected, _actual)) {
              world._manager.removeExpiredPrimaryKeys();
            }
          }
          startConsuming();
          description = "start consuming " + _consuming._name;
        } else if (choice < 50 && _consumedRows < _consuming._rows.size()) {
          int numRows = 1 + _random.nextInt(20);
          consume(numRows);
          description = "consume " + numRows + " rows";
        } else if (_divergent && choice < 56) {
          description = "drop consuming " + _consuming._name;
          for (World world : List.of(_expected, _actual)) {
            world._manager.doRemoveSegment(world._segments.remove(_consuming._name));
          }
          _consuming = null;
        } else if (choice < 70) {
          description = "commit " + _consuming._name;
          commit();
        } else if (choice < 82) {
          upload();
          description = "upload segment";
        } else {
          String name = randomImmutable();
          if (name == null) {
            continue;
          }
          if (choice < 92) {
            List<Row> rows = new ArrayList<>();
            int minComparisonValue = _sequenceNumber * _comparisonDrift;
            for (int i = 0; i < 5 + _random.nextInt(40); i++) {
              rows.add(new Row(makeKey(_random, _random.nextInt(_numKeys)),
                  minComparisonValue + _random.nextInt(_maxComparisonValue), _withDeletes && _random.nextInt(10) == 0));
            }
            reload(name, rows);
            description = "reload " + name;
          } else {
            remove(name);
            description = "remove " + name;
          }
        }
        assertSameState(_expected, _actual, "step " + step + ": " + description);
      }
      assertSegmentRefCounts(_actual._manager);
    }
  }

  /// Stored segment ids must match the registry's reference counts, and no unreferenced retired id may linger.
  static void assertSegmentRefCounts(BasePartitionUpsertMetadataManager manager) {
    PrimaryKeyLocationStore store = ((RocksDBPartitionUpsertMetadataManager) manager)._store;
    Map<Integer, Long> storedRefs = new HashMap<>();
    for (int columnFamily : new int[]{PrimaryKeyLocationStore.PRIMARY, PrimaryKeyLocationStore.PREVIOUS}) {
      try (RocksIterator iterator = store.getPartitionStore().newIterator(columnFamily)) {
        for (iterator.seekToFirst(); iterator.isValid(); iterator.next()) {
          storedRefs.merge(MetadataCodec.decodeSegmentId(iterator.value()), 1L, Long::sum);
        }
      }
    }
    SegmentRegistry registry = store.getSegmentRegistry();
    storedRefs.forEach((id, count) -> assertEquals(registry.getRefCount(id), (long) count, "refCount of " + id));
    for (int retiredId : registry.getRetiredIds()) {
      assertTrue(storedRefs.containsKey(retiredId), "Unreferenced retired segment id: " + retiredId);
    }
  }

  static void closeQuietly(BasePartitionUpsertMetadataManager manager) {
    try {
      manager.stop();
      manager.close();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @DataProvider
  public Object[][] fullUpsertCases() {
    List<Object[]> cases = new ArrayList<>();
    for (HashFunction hashFunction : new HashFunction[]{HashFunction.NONE, HashFunction.MURMUR3}) {
      for (boolean withDeletes : new boolean[]{false, true}) {
        for (long seed = 1; seed <= 3; seed++) {
          cases.add(new Object[]{hashFunction, withDeletes, seed});
        }
      }
    }
    return cases.toArray(new Object[0][]);
  }

  /// A partial-upsert handler that records which previous row was merged into the new row.
  static PartialUpsertHandler recordingPartialUpsertHandler() {
    PartialUpsertHandler handler = mock(PartialUpsertHandler.class);
    doAnswer(invocation -> {
      LazyRow previousRow = invocation.getArgument(0);
      GenericRow newRow = invocation.getArgument(1);
      newRow.putValue(MERGED_FROM, previousRow.getValue(TAG_COLUMN));
      return null;
    }).when(handler).merge(any(), any(), any());
    return handler;
  }

  @Test(dataProvider = "fullUpsertCases")
  public void testPartialUpsertParity(HashFunction hashFunction, boolean withDeletes, long seed) {
    UpsertContext context =
        contextBuilder(hashFunction, withDeletes).setPartialUpsertHandler(recordingPartialUpsertHandler()).build();
    World expected = new World(new ConcurrentMapPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context));
    World actual =
        new World(new RocksDBPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context, storeConfig()));
    try {
      Driver driver = new Driver(seed, withDeletes, 300, 40, expected, actual);
      driver.run(400);
      assertTrue(driver._numMerges > 100, "Too few partial-upsert merges: " + driver._numMerges);
    } finally {
      closeQuietly(expected._manager);
      closeQuietly(actual._manager);
    }
  }

  @Test(dataProvider = "fullUpsertCases")
  public void testPartialUpsertRevertParity(HashFunction hashFunction, boolean withDeletes, long seed) {
    ConsumingSegmentConsistencyModeListener.getInstance()
        .setMode(ConsumingSegmentConsistencyModeListener.Mode.PROTECTED);
    UpsertContext context =
        contextBuilder(hashFunction, withDeletes).setPartialUpsertHandler(recordingPartialUpsertHandler()).build();
    World expected = new World(new ConcurrentMapPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context));
    RocksDBPartitionUpsertMetadataManager rocksDBManager =
        new RocksDBPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context, storeConfig());
    World actual = new World(rocksDBManager);
    try {
      Driver driver = new Driver(seed, withDeletes, 300, 40, expected, actual);
      driver._divergent = true;
      driver.run(400);
      assertEquals(rocksDBManager.getPrevKeyToRecordLocationSize(),
          ((ConcurrentMapPartitionUpsertMetadataManager) expected._manager).getPrevKeyToRecordLocationSize());
    } finally {
      ConsumingSegmentConsistencyModeListener.getInstance().reset();
      closeQuietly(expected._manager);
      closeQuietly(actual._manager);
    }
  }

  @DataProvider
  public Object[][] ttlCases() {
    List<Object[]> cases = new ArrayList<>();
    for (boolean partial : new boolean[]{false, true}) {
      for (long seed = 1; seed <= 3; seed++) {
        // metadataTTL only, deletedKeysTTL only (needs deletes)
        cases.add(new Object[]{partial, 30.0, 0.0, false, seed});
        cases.add(new Object[]{partial, 0.0, 20.0, true, seed});
      }
    }
    return cases.toArray(new Object[0][]);
  }

  @Test(dataProvider = "ttlCases")
  public void testTTLParity(boolean partial, double metadataTTL, double deletedKeysTTL, boolean withDeletes,
      long seed) {
    UpsertContext.Builder builder = contextBuilder(HashFunction.NONE, withDeletes).setEnableSnapshot(true)
        .setMetadataTTL(metadataTTL).setDeletedKeysTTL(deletedKeysTTL);
    if (partial) {
      builder.setPartialUpsertHandler(recordingPartialUpsertHandler());
    }
    UpsertContext context = builder.build();
    World expected = new World(new ConcurrentMapPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context));
    World actual =
        new World(new RocksDBPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context, storeConfig()));
    try {
      Driver driver = new Driver(seed, withDeletes, 300, 40, expected, actual);
      driver._comparisonDrift = 4;
      driver._ttlScans = true;
      driver.run(400);
      assertTrue(expected._manager.getNumPrimaryKeys() < 300, "TTL never removed keys");
    } finally {
      closeQuietly(expected._manager);
      closeQuietly(actual._manager);
    }
  }

  @Test
  public void testAsyncTTLScanRunsOffThreadAndCloseWaitsForIt()
      throws Exception {
    UpsertContext context =
        contextBuilder(HashFunction.NONE, false).setEnableSnapshot(true).setMetadataTTL(10).build();
    RocksDBMetadataStoreConfig asyncConfig = RocksDBMetadataStoreConfig.from(null,
        Map.of("rocksdb.dataDir", new File(TEMP_DIR, "rocksdb-async").getAbsolutePath(),
            "rocksdb.ttlScanMaxKeysPerSecond", "20000"));
    RocksDBPartitionUpsertMetadataManager manager =
        new RocksDBPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context, asyncConfig);
    SegmentSpec spec = new SegmentSpec(new LLCSegmentName(RAW_TABLE_NAME, 0, 0, 1_700_000_000_000L).toString(),
        1_700_000_000_000L, new ArrayList<>());
    for (int i = 0; i < 10_000; i++) {
      spec._rows.add(new Row(makeKey(null, i), i < 9_000 ? 0 : 100, false));
    }
    MutableSegment segment = mockMutableSegment(spec, new ThreadSafeMutableRoaringBitmap(), null);
    for (int docId = 0; docId < spec._rows.size(); docId++) {
      manager.addRecord(segment, recordInfo(spec._rows, docId));
    }
    assertEquals(manager.getNumPrimaryKeys(), 10_000);
    long startNs = System.nanoTime();
    manager.removeExpiredPrimaryKeys();
    // At 20K keys/s the scan of 10K keys takes about 0.5s; scheduling it must not.
    assertTrue(System.nanoTime() - startNs < 200_000_000L, "TTL scan blocked the caller");
    manager.stop();
    manager.close();
    assertEquals(manager.getNumPrimaryKeys(), 1_000);
  }

  @DataProvider
  public Object[][] restartCases() {
    List<Object[]> cases = new ArrayList<>();
    for (HashFunction hashFunction : new HashFunction[]{HashFunction.NONE, HashFunction.MURMUR3}) {
      for (boolean withDeletes : new boolean[]{false, true}) {
        for (boolean partial : new boolean[]{false, true}) {
          for (long seed = 1; seed <= 2; seed++) {
            cases.add(new Object[]{hashFunction, withDeletes, partial, seed});
          }
        }
      }
    }
    return cases.toArray(new Object[0][]);
  }

  /// Restart: both managers are rebuilt by preloading every committed segment with its validDocIds snapshot (small
  /// thresholds exercise SST ingest, write batches and chunking), then keep consuming in lockstep.
  @Test(dataProvider = "restartCases")
  public void testRestartWithPreloadParity(HashFunction hashFunction, boolean withDeletes, boolean partial,
      long seed) {
    UpsertContext.Builder builder = contextBuilder(hashFunction, withDeletes).setEnableSnapshot(true);
    if (partial) {
      builder.setPartialUpsertHandler(recordingPartialUpsertHandler());
    }
    UpsertContext context = builder.build();
    RocksDBMetadataStoreConfig preloadConfig = RocksDBMetadataStoreConfig.from(null,
        Map.of("rocksdb.dataDir", new File(TEMP_DIR, "rocksdb").getAbsolutePath(), "rocksdb.preloadSstMinKeys",
            "10", "rocksdb.preloadBatchKeys", "16", "rocksdb.asyncTtlScan", "false"));

    World expected = new World(new ConcurrentMapPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context));
    World actual =
        new World(new RocksDBPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context, preloadConfig));
    Driver driver;
    try {
      driver = new Driver(seed, withDeletes, 300, 40, expected, actual);
      driver.run(200);
    } finally {
      closeQuietly(expected._manager);
      closeQuietly(actual._manager);
    }

    World restartedExpected =
        new World(new ConcurrentMapPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context));
    World restartedActual =
        new World(new RocksDBPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context, preloadConfig));
    try {
      int numPreloadedKeys = 0;
      for (SegmentSpec spec : driver._immutableSpecs.values()) {
        MutableRoaringBitmap snapshot = expected._segments.get(spec._name).getValidDocIds().getMutableRoaringBitmap();
        List<Row> rows = spec._rows;
        numPreloadedKeys += snapshot.getCardinality();
        for (World world : List.of(restartedExpected, restartedActual)) {
          ThreadSafeMutableRoaringBitmap validDocIds = new ThreadSafeMutableRoaringBitmap();
          ThreadSafeMutableRoaringBitmap queryableDocIds = withDeletes ? new ThreadSafeMutableRoaringBitmap() : null;
          ImmutableSegmentImpl segment = mockImmutableSegment(spec, validDocIds, queryableDocIds);
          List<RecordInfo> snapshotRecords = new ArrayList<>();
          snapshot.forEach((int docId) -> snapshotRecords.add(recordInfo(rows, docId)));
          world._manager.doPreloadSegment(segment, validDocIds, queryableDocIds, snapshotRecords.iterator());
          world._segments.put(spec._name, segment);
          assertEquals(validDocIds.getMutableRoaringBitmap(), snapshot, "Preload changed validDocIds of " + spec._name);
        }
      }
      assertTrue(numPreloadedKeys > 0);
      assertEquals(restartedActual._manager.getNumPrimaryKeys(), numPreloadedKeys);
      assertSameState(restartedExpected, restartedActual, "preload");

      Driver restartedDriver = new Driver(seed + 1000, withDeletes, 300, 40, restartedExpected, restartedActual);
      restartedDriver._sequenceNumber = driver._sequenceNumber + 1;
      restartedDriver._immutableSpecs.putAll(driver._immutableSpecs);
      restartedDriver.run(200);
    } finally {
      closeQuietly(restartedExpected._manager);
      closeQuietly(restartedActual._manager);
    }
  }

  @Test(dataProvider = "fullUpsertCases")
  public void testFullUpsertParity(HashFunction hashFunction, boolean withDeletes, long seed) {
    UpsertContext context = contextBuilder(hashFunction, withDeletes).build();
    World expected = new World(new ConcurrentMapPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context));
    World actual =
        new World(new RocksDBPartitionUpsertMetadataManager(REALTIME_TABLE_NAME, 0, context, storeConfig()));
    try {
      new Driver(seed, withDeletes, 300, 40, expected, actual).run(400);
    } finally {
      closeQuietly(expected._manager);
      closeQuietly(actual._manager);
    }
  }
}
