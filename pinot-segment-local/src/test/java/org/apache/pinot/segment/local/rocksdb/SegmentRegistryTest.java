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

import java.util.Set;
import org.apache.pinot.segment.spi.IndexSegment;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;


public class SegmentRegistryTest {

  @Test
  public void testRetiredIdIsReleasedWithItsLastReference() {
    SegmentRegistry registry = new SegmentRegistry();
    IndexSegment referenced = mock(IndexSegment.class);
    int referencedId = registry.getOrAssignId(referenced);
    registry.addRef(referencedId);
    registry.addRef(referencedId);
    registry.retire(referenced);
    registry.removeRef(referencedId);
    assertSame(registry.getSegment(referencedId), referenced);
    registry.removeRef(referencedId);
    assertNull(registry.getSegment(referencedId));
    assertEquals(registry.getNumRetired(), 0);

    // A segment that no entry references is released when it is retired.
    IndexSegment unreferenced = mock(IndexSegment.class);
    int unreferencedId = registry.getOrAssignId(unreferenced);
    registry.retire(unreferenced);
    assertNull(registry.getSegment(unreferencedId));

    // Live segments stay resolvable without references.
    IndexSegment live = mock(IndexSegment.class);
    int liveId = registry.getOrAssignId(live);
    registry.addRef(liveId);
    registry.removeRef(liveId);
    assertSame(registry.getSegment(liveId), live);
  }

  @Test
  public void testIdsArePerObjectAndNeverReused() {
    SegmentRegistry registry = new SegmentRegistry();
    IndexSegment first = mock(IndexSegment.class);
    IndexSegment reloaded = mock(IndexSegment.class);
    int firstId = registry.getOrAssignId(first);
    assertEquals(registry.getOrAssignId(first), firstId);
    int reloadedId = registry.getOrAssignId(reloaded);
    assertNotEquals(reloadedId, firstId);
    assertSame(registry.getSegment(firstId), first);
    assertEquals(registry.getId(reloaded), reloadedId);
    assertEquals(registry.getId(mock(IndexSegment.class)), -1);

    registry.addRef(firstId);
    registry.retire(first);
    // Referenced retired ids still resolve until released, so keys left behind by an out-of-TTL removal keep working.
    assertSame(registry.getSegment(firstId), first);
    assertEquals(registry.getId(first), -1);
    assertEquals(registry.releaseRetired(Set.of(firstId)), 0);
    assertSame(registry.getSegment(firstId), first);
    assertEquals(registry.releaseRetired(Set.of()), 1);
    assertNull(registry.getSegment(firstId));

    // Registering the same object again yields a fresh id.
    int newId = registry.getOrAssignId(first);
    assertNotEquals(newId, firstId);
    assertNotEquals(newId, reloadedId);
  }
}
