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
import org.rocksdb.RocksIterator;


/**
 * The dedup primary-key map on RocksDB: primary key bytes to (segment, dedup time).
 *
 * <p>{@link #compute} has the contract of {@code ConcurrentHashMap.compute} (see {@link PrimaryKeyLocationStore}), so
 * the RocksDB dedup manager keeps the in-memory manager's logic line for line. Segment ids are reference counted in
 * the {@link SegmentRegistry}, and an entry whose segment id was released resolves to no entry. Thread-safe.
 */
@ThreadSafe
public class DedupKeyStore implements AutoCloseable {
  private static final int COLUMN_FAMILY = 0;
  private static final int DELETE_BATCH_SIZE = 10_000;

  /// A decoded entry. Equivalent to the in-memory manager's {@code Pair<IndexSegment, Double>}.
  public static final class Entry {
    private final IndexSegment _segment;
    private final double _dedupTime;

    public Entry(IndexSegment segment, double dedupTime) {
      _segment = segment;
      _dedupTime = dedupTime;
    }

    public IndexSegment getSegment() {
      return _segment;
    }

    public double getDedupTime() {
      return _dedupTime;
    }
  }

  private final RocksDBPartitionStore _store;
  private final SegmentRegistry _segmentRegistry = new SegmentRegistry();
  private final StripedLocks _locks = new StripedLocks(StripedLocks.DEFAULT_NUM_STRIPES);
  private final AtomicLong _numKeys = new AtomicLong();
  private final AtomicLong _numStaleEntries = new AtomicLong();

  public DedupKeyStore(File dir, RocksDBMetadataStoreConfig config) {
    _store = new RocksDBPartitionStore(dir, List.of("default"), config);
  }

  public SegmentRegistry getSegmentRegistry() {
    return _segmentRegistry;
  }

  public RocksDBPartitionStore getPartitionStore() {
    return _store;
  }

  @Nullable
  private Entry decode(byte[] value) {
    IndexSegment segment = _segmentRegistry.getSegment(MetadataCodec.decodeSegmentId(value));
    if (segment == null) {
      _numStaleEntries.incrementAndGet();
      return null;
    }
    return new Entry(segment, MetadataCodec.decodeDedupTime(value));
  }

  private byte[] encode(Entry entry) {
    return MetadataCodec.encodeDedupValue(_segmentRegistry.getOrAssignId(entry.getSegment()), entry.getDedupTime());
  }

  /**
   * Atomically updates the entry of {@code key}: returning {@code null} deletes it, returning the same instance leaves
   * the store unchanged, and any other value is written.
   */
  @Nullable
  public Entry compute(byte[] key, BiFunction<byte[], Entry, Entry> function) {
    ReentrantLock lock = _locks.get(key);
    lock.lock();
    try {
      byte[] currentValue = _store.get(COLUMN_FAMILY, key);
      Entry current = currentValue != null ? decode(currentValue) : null;
      Entry updated = function.apply(key, current);
      if (updated == null) {
        if (currentValue != null) {
          _store.delete(COLUMN_FAMILY, key);
          _numKeys.decrementAndGet();
          _segmentRegistry.removeRef(MetadataCodec.decodeSegmentId(currentValue));
        }
      } else if (updated != current) {
        byte[] updatedValue = encode(updated);
        _store.put(COLUMN_FAMILY, key, updatedValue);
        _segmentRegistry.addRef(MetadataCodec.decodeSegmentId(updatedValue));
        if (currentValue == null) {
          _numKeys.incrementAndGet();
        } else {
          _segmentRegistry.removeRef(MetadataCodec.decodeSegmentId(currentValue));
        }
      }
      return updated;
    } finally {
      lock.unlock();
    }
  }

  /// Like {@link #compute}, but does nothing when the key is absent.
  @Nullable
  public Entry computeIfPresent(byte[] key, BiFunction<byte[], Entry, Entry> function) {
    return compute(key, (k, current) -> current != null ? function.apply(k, current) : null);
  }

  /// Unconditionally sets the entry of {@code key}.
  public void put(byte[] key, Entry entry) {
    compute(key, (k, current) -> entry);
  }

  /**
   * Deletes every entry with a dedup time smaller than {@code smallestTimeToKeep}, unless it changed while the scan
   * ran. Afterwards, releases retired segment ids that no entry references.
   *
   * @param maxKeysPerSecond rate limit of the scan; 0 means unlimited
   * @return number of entries deleted
   */
  public long removeOlderThan(double smallestTimeToKeep, long maxKeysPerSecond) {
    long numDeleted = 0;
    long numKeys = 0;
    Set<Integer> referencedIds = new HashSet<>();
    long startNs = System.nanoTime();
    List<byte[]> toDelete = new ArrayList<>();
    List<byte[]> toDeleteValues = new ArrayList<>();
    try (RocksIterator iterator = _store.newIterator(COLUMN_FAMILY)) {
      for (iterator.seekToFirst(); iterator.isValid(); iterator.next()) {
        byte[] value = iterator.value();
        numKeys++;
        if (MetadataCodec.decodeDedupTime(value) < smallestTimeToKeep
            || _segmentRegistry.getSegment(MetadataCodec.decodeSegmentId(value)) == null) {
          toDelete.add(iterator.key());
          toDeleteValues.add(value);
          if (toDelete.size() >= DELETE_BATCH_SIZE) {
            numDeleted += deleteIfUnchanged(toDelete, toDeleteValues);
          }
        } else {
          referencedIds.add(MetadataCodec.decodeSegmentId(value));
        }
        if (maxKeysPerSecond > 0 && numKeys % 1000 == 0) {
          PrimaryKeyLocationStore.throttle(numKeys, maxKeysPerSecond, startNs);
        }
      }
    }
    numDeleted += deleteIfUnchanged(toDelete, toDeleteValues);
    _segmentRegistry.releaseRetired(referencedIds);
    return numDeleted;
  }

  private long deleteIfUnchanged(List<byte[]> keys, List<byte[]> expectedValues) {
    long numDeleted = 0;
    for (int i = 0; i < keys.size(); i++) {
      byte[] key = keys.get(i);
      ReentrantLock lock = _locks.get(key);
      lock.lock();
      try {
        byte[] current = _store.get(COLUMN_FAMILY, key);
        if (current != null && Arrays.equals(current, expectedValues.get(i))) {
          _store.delete(COLUMN_FAMILY, key);
          _numKeys.decrementAndGet();
          _segmentRegistry.removeRef(MetadataCodec.decodeSegmentId(current));
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

  public long getNumKeys() {
    return _numKeys.get();
  }

  public long getNumStaleEntries() {
    return _numStaleEntries.get();
  }

  @Override
  public void close() {
    _store.close();
    _segmentRegistry.clear();
  }
}
