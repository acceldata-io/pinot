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


/// Coarse permissions of the native authorization model. Every fine-grained action maps to exactly one of
/// `READ`..`ADMIN`; `ALL` exists only on the granting side and implies every other permission.
public enum Permission {
  READ, CREATE, UPDATE, DELETE, ADMIN, ALL;

  /// @throws IllegalArgumentException for an unknown name
  public static Permission fromName(String name) {
    try {
      return valueOf(name.trim().toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Unknown permission '" + name.trim() + "'; expected one of READ, CREATE, "
          + "UPDATE, DELETE, ADMIN, ALL");
    }
  }

  /// Whether holding this permission grants `required`.
  public boolean grants(Permission required) {
    return this == ALL || this == required;
  }
}
