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

import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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
 * <p>An id stays resolvable after {@link #retire} until {@link #releaseRetired} drops it, because keys can still point
 * at a removed segment until the metadata TTL scan deletes them (the base manager skips removing out-of-TTL segments).
 * The in-memory map keeps such segments reachable the same way.
 *
 * <p>Thread-safe. {@link #getOrAssignId} is on the ingestion path and is lock-free for the last used segment.
 */
@ThreadSafe
public final class SegmentRegistry {
  private final Map<Integer, IndexSegment> _idToSegment = new ConcurrentHashMap<>();
  private final Set<Integer> _retiredIds = ConcurrentHashMap.newKeySet();
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

  /// Marks a segment as removed from the manager. Its id stays resolvable until {@link #releaseRetired} drops it.
  public void retire(IndexSegment segment) {
    synchronized (this) {
      Integer id = _segmentToId.remove(segment);
      if (id != null) {
        _retiredIds.add(id);
      }
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

  public synchronized void clear() {
    _segmentToId.clear();
    _idToSegment.clear();
    _retiredIds.clear();
    _lastLookup = null;
  }
}
