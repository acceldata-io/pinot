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
package org.apache.pinot.plugin.auth.spi;

import javax.annotation.Nullable;


/// Minimal access to a cluster-wide setting shared by all components (for example a ZooKeeper-backed cluster config),
/// used by [AuthMethodConsistency]. Implementations must make [#putIfAbsent] atomic.
public interface ClusterSettingStore {
  /// Stores the value if the key has none yet.
  ///
  /// @return the value stored for the key after the call (the existing value, or the given one)
  String putIfAbsent(String key, String value);

  /// @return the value of the key, or `null`
  @Nullable
  String get(String key);
}
