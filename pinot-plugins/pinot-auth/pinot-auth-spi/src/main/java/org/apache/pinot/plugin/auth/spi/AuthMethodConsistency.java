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

import java.util.Objects;


/// Makes every controller, broker, server and Minion of a cluster use the same authentication method. The first
/// component to start records its method in the cluster-wide store; a component started later with a different method
/// refuses to start. Changing the method therefore means a full stop of the cluster and a change of the recorded value
/// by the operator (or the management tooling) before restarting.
public final class AuthMethodConsistency {
  /// Cluster-wide key holding the recorded method.
  public static final String CLUSTER_METHOD_KEY = AuthMethodSelector.METHOD_CONFIG;

  private AuthMethodConsistency() {
  }

  /// Records the method if none is recorded, otherwise checks it against the recorded one.
  ///
  /// @param component name used in the error, e.g. `Broker_host_8099`
  /// @throws IllegalStateException if the cluster records another method
  public static void verify(AuthMethod localMethod, ClusterSettingStore store, String component) {
    Objects.requireNonNull(localMethod, "localMethod");
    String recorded = store.putIfAbsent(CLUSTER_METHOD_KEY, localMethod.getConfigValue());
    AuthMethod clusterMethod;
    try {
      clusterMethod = AuthMethod.fromConfigValue(recorded);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("Cluster setting " + CLUSTER_METHOD_KEY + " holds an unknown method '" + recorded
          + "'", e);
    }
    if (clusterMethod != localMethod) {
      throw new IllegalStateException(component + " is configured with " + AuthMethodSelector.METHOD_CONFIG + "="
          + localMethod.getConfigValue() + ", but the cluster uses " + clusterMethod.getConfigValue() + ". Every "
          + "controller, broker, server and Minion must use the same authentication method; methods are never mixed.");
    }
  }
}
