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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiFunction;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.pinot.segment.spi.IndexSegment;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;
import org.rocksdb.WriteBatch;


/**
 * The upsert primary-key map on RocksDB: primary key bytes to (segment, doc id, comparison value), plus the
 * previous-location map that partial-upsert tables use to revert a consuming segment.
 *
 * <p>{@link #compute} has the contract of {@code ConcurrentHashMap.compute}: the function runs while the key's stripe
 * lock is held, returning {@code null} deletes the key, returning the same {@link Location} instance leaves the store
 * unchanged, and any other value is written. That lets the RocksDB managers keep the in-memory managers' logic line
 * for line.
 *
 * <p>A stored location whose segment id was released from the {@link SegmentRegistry} resolves to no location and is
 * counted by {@link #getNumStaleLocations()}. Thread-safe.
 */
@ThreadSafe
@SuppressWarnings("rawtypes")
public class PrimaryKeyLocationStore implements AutoCloseable {
  public static final int PRIMARY = 0;
  public static final int PREVIOUS = 1;
  private static final List<String> COLUMN_FAMILIES = List.of("default", "previous");
  private static final int DELETE_BATCH_SIZE = 10_000;

  /// A decoded record location. Equivalent to the in-memory managers' {@code RecordLocation}.
  public static final class Location {
    private final IndexSegment _segment;
    private final int _docId;
    private final Comparable _comparisonValue;

    public Location(IndexSegment segment, int docId, Comparable comparisonValue) {
      _segment = segment;
      _docId = docId;
      _comparisonValue = comparisonValue;
    }

    public IndexSegment getSegment() {
      return _segment;
    }

    public int getDocId() {
      return _docId;
    }

    public Comparable getComparisonValue() {
      return _comparisonValue;
    }
  }

  /// Callback of {@link #scanPrimary}. Return {@code true} to delete the entry if it is still unchanged.
  @FunctionalInterface
  public interface ScanVisitor {
    boolean visit(byte[] key, Location location);
  }

  private final RocksDBPartitionStore _store;
  private final SegmentRegistry _segmentRegistry = new SegmentRegistry();
  private final StripedLocks _locks = new StripedLocks(StripedLocks.DEFAULT_NUM_STRIPES);
  private final AtomicLong _numPrimaryKeys = new AtomicLong();
  private final AtomicLong _numPreviousKeys = new AtomicLong();
  private final AtomicLong _numStaleLocations = new AtomicLong();

  public PrimaryKeyLocationStore(File dir, RocksDBMetadataStoreConfig config) {
    _store = new RocksDBPartitionStore(dir, COLUMN_FAMILIES, config);
  }

  public SegmentRegistry getSegmentRegistry() {
    return _segmentRegistry;
  }

  public RocksDBPartitionStore getPartitionStore() {
    return _store;
  }

  public ReentrantLock lock(byte[] key) {
    ReentrantLock lock = _locks.get(key);
    lock.lock();
    return lock;
  }

  /// Reads a location without locking. Use inside {@link #compute} or when a racy read is acceptable.
  @Nullable
  public Location get(int columnFamily, byte[] key) {
    byte[] value = _store.get(columnFamily, key);
    return value != null ? decode(value) : null;
  }

  @Nullable
  private Location decode(byte[] value) {
    IndexSegment segment = _segmentRegistry.getSegment(MetadataCodec.decodeSegmentId(value));
    if (segment == null) {
      _numStaleLocations.incrementAndGet();
      return null;
    }
    return new Location(segment, MetadataCodec.decodeDocId(value), MetadataCodec.decodeComparisonValue(value));
  }

  private byte[] encode(Location location) {
    return MetadataCodec.encodeUpsertValue(_segmentRegistry.getOrAssignId(location.getSegment()),
        location.getDocId(), location.getComparisonValue());
  }

  private void addRef(byte[] value) {
    _segmentRegistry.addRef(MetadataCodec.decodeSegmentId(value));
  }

  private void removeRef(byte[] value) {
    _segmentRegistry.removeRef(MetadataCodec.decodeSegmentId(value));
  }

  /**
   * Atomically updates the primary location of {@code key}. See the class Javadoc for the contract.
   *
   * @return the new location, or {@code null} if the key is absent afterwards
   */
  @Nullable
  public Location compute(byte[] key, BiFunction<byte[], Location, Location> function) {
    ReentrantLock lock = lock(key);
    try {
      byte[] currentValue = _store.get(PRIMARY, key);
      Location current = currentValue != null ? decode(currentValue) : null;
      Location updated = function.apply(key, current);
      if (updated == null) {
        if (currentValue != null) {
          _store.delete(PRIMARY, key);
          _numPrimaryKeys.decrementAndGet();
          removeRef(currentValue);
        }
      } else if (updated != current) {
        byte[] updatedValue = encode(updated);
        _store.put(PRIMARY, key, updatedValue);
        addRef(updatedValue);
        if (currentValue == null) {
          _numPrimaryKeys.incrementAndGet();
        } else {
          removeRef(currentValue);
        }
      }
      return updated;
    } finally {
      lock.unlock();
    }
  }

  /// Like {@link #compute}, but does nothing when the key is absent.
  @Nullable
  public Location computeIfPresent(byte[] key, BiFunction<byte[], Location, Location> function) {
    return compute(key, (k, current) -> current != null ? function.apply(k, current) : null);
  }

  /// Unconditionally sets the primary location. Caller holds the key lock or knows the key is not contended.
  public void put(byte[] key, Location location) {
    ReentrantLock lock = lock(key);
    try {
      byte[] currentValue = _store.get(PRIMARY, key);
      byte[] value = encode(location);
      _store.put(PRIMARY, key, value);
      addRef(value);
      if (currentValue == null) {
        _numPrimaryKeys.incrementAndGet();
      } else {
        removeRef(currentValue);
      }
    } finally {
      lock.unlock();
    }
  }

  /**
   * Writes many primary locations of keys that are known to be absent and uncontended, e.g. while preloading the
   * disjoint valid docs of a snapshot. Large inputs are sorted and ingested as one SST file.
   */
  public void putAllAbsent(List<byte[]> keys, List<Location> locations, int sstMinKeys) {
    int numKeys = keys.size();
    if (numKeys == 0) {
      return;
    }
    Integer[] order = new Integer[numKeys];
    for (int i = 0; i < numKeys; i++) {
      order[i] = i;
    }
    // Stable sort, so the last value of a duplicated key wins, as consecutive puts would.
    Arrays.sort(order, (a, b) -> Arrays.compareUnsigned(keys.get(a), keys.get(b)));
    List<byte[]> sortedKeys = new ArrayList<>(numKeys);
    List<byte[]> sortedValues = new ArrayList<>(numKeys);
    for (int i = 0; i < numKeys; i++) {
      int index = order[i];
      if (i + 1 < numKeys && Arrays.equals(keys.get(index), keys.get(order[i + 1]))) {
        continue;
      }
      sortedKeys.add(keys.get(index));
      sortedValues.add(encode(locations.get(index)));
    }
    if (sstMinKeys > 0 && sortedKeys.size() >= sstMinKeys) {
      _store.ingestSorted(PRIMARY, sortedKeys, sortedValues);
    } else {
      try (WriteBatch batch = _store.newWriteBatch()) {
        for (int i = 0; i < sortedKeys.size(); i++) {
          batch.put(_store.getHandle(PRIMARY), sortedKeys.get(i), sortedValues.get(i));
        }
        _store.write(batch);
      } catch (RocksDBException e) {
        throw new RocksDBMetadataStoreException("Failed to build write batch", e);
      }
    }
    for (byte[] value : sortedValues) {
      addRef(value);
    }
    _numPrimaryKeys.addAndGet(sortedKeys.size());
  }

  @Nullable
  public Location getPrevious(byte[] key) {
    return get(PREVIOUS, key);
  }

  public void putPrevious(byte[] key, Location location) {
    byte[] currentValue = _store.get(PREVIOUS, key);
    byte[] value = encode(location);
    _store.put(PREVIOUS, key, value);
    addRef(value);
    if (currentValue == null) {
      _numPreviousKeys.incrementAndGet();
    } else {
      removeRef(currentValue);
    }
  }

  public void removePrevious(byte[] key) {
    byte[] currentValue = _store.get(PREVIOUS, key);
    if (currentValue != null) {
      _store.delete(PREVIOUS, key);
      _numPreviousKeys.decrementAndGet();
      removeRef(currentValue);
    }
  }

  /// Deletes every previous location, taking each key's lock.
  public void clearPrevious() {
    try (RocksIterator iterator = _store.newIterator(PREVIOUS)) {
      for (iterator.seekToFirst(); iterator.isValid(); iterator.next()) {
        byte[] key = iterator.key();
        ReentrantLock lock = lock(key);
        try {
          removePrevious(key);
        } finally {
          lock.unlock();
        }
      }
    }
  }

  /**
   * Visits every primary entry; entries for which the visitor returns {@code true} are deleted if their stored value
   * did not change in the meantime. Afterwards, releases retired segment ids that no entry references.
   *
   * @param maxKeysPerSecond rate limit of the scan; 0 means unlimited
   * @return number of entries deleted
   */
  public long scanPrimary(ScanVisitor visitor, long maxKeysPerSecond) {
    long numDeleted = 0;
    long numKeys = 0;
    Set<Integer> referencedIds = new HashSet<>();
    long startNs = System.nanoTime();
    List<byte[]> toDelete = new ArrayList<>();
    List<byte[]> toDeleteValues = new ArrayList<>();
    try (RocksIterator iterator = _store.newIterator(PRIMARY)) {
      for (iterator.seekToFirst(); iterator.isValid(); iterator.next()) {
        byte[] key = iterator.key();
        byte[] value = iterator.value();
        numKeys++;
        Location location = decode(value);
        if (location == null || visitor.visit(key, location)) {
          toDelete.add(key);
          toDeleteValues.add(value);
          if (toDelete.size() >= DELETE_BATCH_SIZE) {
            numDeleted += deleteIfUnchanged(toDelete, toDeleteValues);
          }
        } else {
          referencedIds.add(MetadataCodec.decodeSegmentId(value));
        }
        if (maxKeysPerSecond > 0 && numKeys % 1000 == 0) {
          throttle(numKeys, maxKeysPerSecond, startNs);
        }
      }
    }
    numDeleted += deleteIfUnchanged(toDelete, toDeleteValues);
    // Keys written during the scan refer to live segments only, so they cannot keep a retired id alive.
    try (RocksIterator iterator = _store.newIterator(PREVIOUS)) {
      for (iterator.seekToFirst(); iterator.isValid(); iterator.next()) {
        referencedIds.add(MetadataCodec.decodeSegmentId(iterator.value()));
      }
    }
    _segmentRegistry.releaseRetired(referencedIds);
    return numDeleted;
  }

  private long deleteIfUnchanged(List<byte[]> keys, List<byte[]> expectedValues) {
    long numDeleted = 0;
    for (int i = 0; i < keys.size(); i++) {
      byte[] key = keys.get(i);
      ReentrantLock lock = lock(key);
      try {
        byte[] current = _store.get(PRIMARY, key);
        if (current != null && Arrays.equals(current, expectedValues.get(i))) {
          _store.delete(PRIMARY, key);
          _numPrimaryKeys.decrementAndGet();
          removeRef(current);
          numDeleted++;
        }
      } finally {
        lock.unlock();
      }
    }
    keys.clear();
    expectedValues.clear();
    return numDeleted;
  }

  static void throttle(long numKeys, long maxKeysPerSecond, long startNs) {
    long expectedNs = numKeys * 1_000_000_000L / maxKeysPerSecond;
    long sleepMs = (expectedNs - (System.nanoTime() - startNs)) / 1_000_000L;
    if (sleepMs > 0) {
      try {
        Thread.sleep(sleepMs);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
  }

  public long getNumPrimaryKeys() {
    return _numPrimaryKeys.get();
  }

  /// Restores the count from a checkpoint. The checkpoint's entries are not re-counted.
  public void restoreNumPrimaryKeys(long numPrimaryKeys) {
    _numPrimaryKeys.set(numPrimaryKeys);
  }

  public int getNumPreviousKeys() {
    return (int) Math.min(Integer.MAX_VALUE, _numPreviousKeys.get());
  }

  public long getNumStaleLocations() {
    return _numStaleLocations.get();
  }

  public boolean isClosed() {
    return _store.isClosed();
  }

  @Override
  public void close() {
    _store.close();
    _segmentRegistry.clear();
  }
}
