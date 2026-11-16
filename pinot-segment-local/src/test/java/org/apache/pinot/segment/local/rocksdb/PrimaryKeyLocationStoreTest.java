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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.segment.local.rocksdb.PrimaryKeyLocationStore.Location;
import org.apache.pinot.segment.spi.IndexSegment;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;


public class PrimaryKeyLocationStoreTest {
  private File _tempDir;
  private PrimaryKeyLocationStore _store;

  @BeforeMethod
  public void setUp()
      throws Exception {
    _tempDir = Files.createTempDirectory("pk-location-store-test").toFile();
    _store = new PrimaryKeyLocationStore(new File(_tempDir, "p0"), RocksDBMetadataStoreConfig.defaults());
  }

  @AfterMethod
  public void tearDown() {
    _store.close();
    FileUtils.deleteQuietly(_tempDir);
  }

  private static byte[] key(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  @Test
  public void testComputeFollowsConcurrentHashMapContract() {
    IndexSegment segment = mock(IndexSegment.class);
    Location inserted = _store.compute(key("a"), (k, current) -> {
      assertNull(current);
      return new Location(segment, 3, 100L);
    });
    assertEquals(_store.getNumPrimaryKeys(), 1);
    Location stored = _store.get(PrimaryKeyLocationStore.PRIMARY, key("a"));
    assertSame(stored.getSegment(), segment);
    assertEquals(stored.getDocId(), 3);
    assertEquals(stored.getComparisonValue(), 100L);
    assertSame(inserted.getSegment(), segment);

    // Returning the current instance leaves the store unchanged.
    _store.compute(key("a"), (k, current) -> current);
    assertEquals(_store.getNumPrimaryKeys(), 1);

    _store.computeIfPresent(key("a"), (k, current) -> new Location(segment, 4, 200L));
    assertEquals(_store.get(PrimaryKeyLocationStore.PRIMARY, key("a")).getDocId(), 4);
    _store.computeIfPresent(key("missing"), (k, current) -> new Location(segment, 1, 1L));
    assertNull(_store.get(PrimaryKeyLocationStore.PRIMARY, key("missing")));

    _store.compute(key("a"), (k, current) -> null);
    assertNull(_store.get(PrimaryKeyLocationStore.PRIMARY, key("a")));
    assertEquals(_store.getNumPrimaryKeys(), 0);
  }

  @Test
  public void testPreviousMap() {
    IndexSegment segment = mock(IndexSegment.class);
    _store.putPrevious(key("a"), new Location(segment, 1, 1L));
    _store.putPrevious(key("a"), new Location(segment, 2, 2L));
    _store.putPrevious(key("b"), new Location(segment, 3, 3L));
    assertEquals(_store.getNumPreviousKeys(), 2);
    assertEquals(_store.getPrevious(key("a")).getDocId(), 2);
    _store.removePrevious(key("a"));
    _store.removePrevious(key("a"));
    assertEquals(_store.getNumPreviousKeys(), 1);
    _store.clearPrevious();
    assertEquals(_store.getNumPreviousKeys(), 0);
    assertNull(_store.getPrevious(key("b")));
  }

  @Test
  public void testScanDeletesOnlyUnchangedEntriesAndReleasesRetiredSegments() {
    IndexSegment oldSegment = mock(IndexSegment.class);
    IndexSegment newSegment = mock(IndexSegment.class);
    for (int i = 0; i < 100; i++) {
      _store.put(key("k" + i), new Location(i < 50 ? oldSegment : newSegment, i, (long) i));
    }
    int oldSegmentId = _store.getSegmentRegistry().getId(oldSegment);
    _store.getSegmentRegistry().retire(oldSegment);
    long deleted = _store.scanPrimary((k, location) -> ((Long) location.getComparisonValue()) < 50, 0);
    assertEquals(deleted, 50);
    assertEquals(_store.getNumPrimaryKeys(), 50);
    assertNull(_store.getSegmentRegistry().getSegment(oldSegmentId));
    assertSame(_store.get(PrimaryKeyLocationStore.PRIMARY, key("k60")).getSegment(), newSegment);
  }

  @Test
  public void testPutAllAbsentUsesSstForLargeBatches() {
    IndexSegment segment = mock(IndexSegment.class);
    List<byte[]> keys = new ArrayList<>();
    List<Location> locations = new ArrayList<>();
    for (int i = 999; i >= 0; i--) {
      keys.add(key("k" + i));
      locations.add(new Location(segment, i, (long) i));
    }
    // A duplicated key keeps the last value, like consecutive puts.
    keys.add(key("k5"));
    locations.add(new Location(segment, 5000, 5000L));
    _store.putAllAbsent(keys, locations, 100);
    assertEquals(_store.getNumPrimaryKeys(), 1000);
    assertEquals(_store.get(PrimaryKeyLocationStore.PRIMARY, key("k5")).getDocId(), 5000);
    assertEquals(_store.get(PrimaryKeyLocationStore.PRIMARY, key("k998")).getDocId(), 998);

    _store.putAllAbsent(List.of(key("small")), List.of(new Location(segment, 1, 1L)), 100);
    assertEquals(_store.getNumPrimaryKeys(), 1001);
  }

  @Test
  public void testConcurrentComputeIsAtomicPerKey()
      throws Exception {
    IndexSegment segment = mock(IndexSegment.class);
    int numThreads = 8;
    int incrementsPerThread = 500;
    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    try {
      List<Future<?>> futures = new ArrayList<>();
      for (int t = 0; t < numThreads; t++) {
        futures.add(executor.submit(() -> {
          for (int i = 0; i < incrementsPerThread; i++) {
            _store.compute(key("counter"), (k, current) -> new Location(segment,
                current == null ? 1 : current.getDocId() + 1, 0L));
          }
        }));
      }
      for (Future<?> future : futures) {
        future.get();
      }
    } finally {
      executor.shutdownNow();
    }
    assertEquals(_store.get(PrimaryKeyLocationStore.PRIMARY, key("counter")).getDocId(),
        numThreads * incrementsPerThread);
    assertEquals(_store.getNumPrimaryKeys(), 1);
  }
}
