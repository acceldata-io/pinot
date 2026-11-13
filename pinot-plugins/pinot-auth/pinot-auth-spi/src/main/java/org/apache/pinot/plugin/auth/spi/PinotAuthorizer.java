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

import java.util.Collections;
import java.util.List;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Decides whether an authenticated principal may perform an [AccessRequest]. One implementation per
/// [AuthorizationMode], selected by [AuthorizerSelector]. Must deny anything it has no rule or policy for. Thread-safe
/// after [#init].
public interface PinotAuthorizer extends AutoCloseable {

  AuthorizationMode getMode();

  /// @param config the mode's settings: `pinot.authz.<mode>.*` without the prefix
  void init(PinotConfiguration config);

  AuthorizationDecision authorize(PinotPrincipal principal, AccessRequest request);

  /// Row filters to apply when the principal queries a table it may read. The broker requires every returned filter
  /// (they are AND-ed), so an authorizer that grants access through several rules with different filters combines
  /// them itself, for example into one `(a) OR (b)` filter.
  ///
  /// @param database the table's database (`default` when the name has none)
  /// @param table the raw table name, without database and type suffix
  /// @return the filters, empty when the principal sees every row
  default List<String> getRowFilters(PinotPrincipal principal, String database, String table) {
    return Collections.emptyList();
  }

  @Override
  default void close() {
  }
}
