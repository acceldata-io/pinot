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

import com.google.common.base.Preconditions;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.concurrent.ThreadSafe;


/**
 * A fixed array of locks indexed by key hash. Holding the lock of a key makes a RocksDB get-modify-put on that key
 * atomic with respect to other threads, which is what {@code ConcurrentHashMap.compute} gives the in-memory managers.
 * Locks are reentrant, so a thread may lock the same stripe again (for example for the previous-location map).
 */
@ThreadSafe
public final class StripedLocks {
  public static final int DEFAULT_NUM_STRIPES = 1024;

  private final ReentrantLock[] _locks;
  private final int _mask;

  public StripedLocks(int numStripes) {
    Preconditions.checkArgument(numStripes > 0 && Integer.bitCount(numStripes) == 1,
        "Number of stripes must be a positive power of 2, got: %s", numStripes);
    _locks = new ReentrantLock[numStripes];
    for (int i = 0; i < numStripes; i++) {
      _locks[i] = new ReentrantLock();
    }
    _mask = numStripes - 1;
  }

  public ReentrantLock get(byte[] key) {
    int hash = Arrays.hashCode(key);
    return _locks[(hash ^ (hash >>> 16)) & _mask];
  }
}
