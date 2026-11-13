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

import java.util.Locale;


/// Who decides authorization for a cluster (`pinot.authz.mode`). Exactly one mode is active: in `ranger` mode the
/// native rules are not loaded at all, and a Ranger outage is covered by the plug-in's cached policies, never by
/// falling back to native rules.
public enum AuthorizationMode {
  NATIVE("native"), RANGER("ranger");

  private final String _configValue;

  AuthorizationMode(String configValue) {
    _configValue = configValue;
  }

  public String getConfigValue() {
    return _configValue;
  }

  /// @throws IllegalArgumentException for an unknown value
  public static AuthorizationMode fromConfigValue(String value) {
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    for (AuthorizationMode mode : values()) {
      if (mode._configValue.equals(normalized)) {
        return mode;
      }
    }
    throw new IllegalArgumentException("Unknown authorization mode '" + value.trim() + "'; expected native or ranger");
  }
}
