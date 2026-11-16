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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.pinot.segment.spi.IndexSegment;


/**
 * Maps segment objects to small integer ids so that a stored record location is a few bytes instead of a Java
 * reference. The in-memory managers compare segments by identity ({@code ==}), so ids are assigned per object: a
 * reloaded segment with the same name gets a new id. Ids are never reused, which keeps a stale stored id from ever
 * resolving to a different segment.
 *
 * <p>The store reports every stored reference with {@link #addRef} and {@link #removeRef}. A retired id is released
 * as soon as no stored entry references it, which is when the in-memory map would let the segment be garbage
 * collected. Until then it stays resolvable, because keys can still point at a removed segment (the base manager skips
 * removing out-of-TTL segments) until the metadata TTL scan deletes them.
 *
 * <p>Thread-safe. {@link #getOrAssignId} is on the ingestion path and is lock-free for the last used segment.
 */
@ThreadSafe
public final class SegmentRegistry {
  private final Map<Integer, IndexSegment> _idToSegment = new ConcurrentHashMap<>();
  private final Set<Integer> _retiredIds = ConcurrentHashMap.newKeySet();
  private final Map<Integer, AtomicLong> _refCounts = new ConcurrentHashMap<>();
  @GuardedBy("this")
  private final IdentityHashMap<IndexSegment, Integer> _segmentToId = new IdentityHashMap<>();
  @GuardedBy("this")
  private int _nextId;

  private static final class LastLookup {
    final IndexSegment _segment;
    final int _id;

    LastLookup(IndexSegment segment, int id) {
      _segment = segment;
      _id = id;
    }
  }

  private volatile LastLookup _lastLookup;

  public int getOrAssignId(IndexSegment segment) {
    LastLookup lastLookup = _lastLookup;
    if (lastLookup != null && lastLookup._segment == segment) {
      return lastLookup._id;
    }
    int id;
    synchronized (this) {
      Integer existing = _segmentToId.get(segment);
      if (existing != null) {
        id = existing;
      } else {
        id = _nextId++;
        _segmentToId.put(segment, id);
        _idToSegment.put(id, segment);
      }
    }
    _lastLookup = new LastLookup(segment, id);
    return id;
  }

  /**
   * Binds {@code segment} to an id restored from a checkpoint. Ids assigned afterwards stay above it, so a restored id
   * is never handed to a different segment.
   */
  public synchronized void bind(IndexSegment segment, int id, long refCount) {
    IndexSegment existing = _idToSegment.get(id);
    if (existing == segment) {
      return;
    }
    Preconditions.checkState(existing == null, "Segment id %s is already bound to %s", id,
        existing != null ? existing.getSegmentName() : null);
    Preconditions.checkState(!_segmentToId.containsKey(segment), "Segment %s is already registered",
        segment.getSegmentName());
    _segmentToId.put(segment, id);
    _idToSegment.put(id, segment);
    if (refCount > 0) {
      _refCounts.put(id, new AtomicLong(refCount));
    }
    if (id >= _nextId) {
      _nextId = id + 1;
    }
  }

  /// Returns the id of a registered segment, or -1 if the segment was never registered.
  public int getId(IndexSegment segment) {
    LastLookup lastLookup = _lastLookup;
    if (lastLookup != null && lastLookup._segment == segment) {
      return lastLookup._id;
    }
    synchronized (this) {
      Integer id = _segmentToId.get(segment);
      return id != null ? id : -1;
    }
  }

  /// Returns the segment of an id, or {@code null} if the id was released.
  @Nullable
  public IndexSegment getSegment(int id) {
    return _idToSegment.get(id);
  }

  /// Records that a stored entry now references {@code id}.
  public void addRef(int id) {
    _refCounts.computeIfAbsent(id, k -> new AtomicLong()).incrementAndGet();
  }

  /// Records that a stored entry no longer references {@code id}; releases the id if it is retired and unreferenced.
  public void removeRef(int id) {
    AtomicLong refCount = _refCounts.get(id);
    if (refCount != null && refCount.decrementAndGet() <= 0 && _retiredIds.contains(id)) {
      releaseIfUnreferenced(id);
    }
  }

  private synchronized void releaseIfUnreferenced(int id) {
    AtomicLong refCount = _refCounts.get(id);
    if (_retiredIds.contains(id) && (refCount == null || refCount.get() <= 0)) {
      _retiredIds.remove(id);
      _idToSegment.remove(id);
      _refCounts.remove(id);
    }
  }

  /// Marks a segment as removed from the manager. Its id stays resolvable while stored entries reference it.
  public void retire(IndexSegment segment) {
    Integer id;
    synchronized (this) {
      id = _segmentToId.remove(segment);
      if (id != null) {
        _retiredIds.add(id);
      }
    }
    if (id != null) {
      releaseIfUnreferenced(id);
    }
    LastLookup lastLookup = _lastLookup;
    if (lastLookup != null && lastLookup._segment == segment) {
      _lastLookup = null;
    }
  }

  /**
   * Drops retired ids that no stored key refers to, so their segment objects can be garbage collected.
   * {@code referencedIds} must cover every id referenced by the store at the time of the call.
   *
   * @return number of ids released
   */
  public int releaseRetired(Set<Integer> referencedIds) {
    int released = 0;
    for (Integer id : _retiredIds) {
      if (!referencedIds.contains(id)) {
        _retiredIds.remove(id);
        _idToSegment.remove(id);
        _refCounts.remove(id);
        released++;
      }
    }
    return released;
  }

  public int getNumSegments() {
    return _idToSegment.size();
  }

  public int getNumRetired() {
    return _retiredIds.size();
  }

  @VisibleForTesting
  public Set<Integer> getRetiredIds() {
    return Set.copyOf(_retiredIds);
  }

  @VisibleForTesting
  public long getRefCount(int id) {
    AtomicLong refCount = _refCounts.get(id);
    return refCount != null ? refCount.get() : 0;
  }

  public synchronized void clear() {
    _segmentToId.clear();
    _idToSegment.clear();
    _retiredIds.clear();
    _refCounts.clear();
    _lastLookup = null;
  }
}
