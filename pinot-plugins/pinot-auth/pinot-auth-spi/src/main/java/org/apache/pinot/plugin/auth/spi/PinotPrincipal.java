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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;


/// The authenticated identity of a request, produced by the cluster's authentication method and consumed by the
/// authorizer (native rules or Ranger). Immutable and thread-safe.
public final class PinotPrincipal {
  private final String _user;
  private final Set<String> _groups;
  private final AuthMethod _method;
  private final boolean _serviceAccount;
  private final Map<String, Object> _claims;

  /// @param user user name after identity mapping; not blank
  /// @param groups group names (may be empty)
  /// @param method the method that authenticated the request
  /// @param serviceAccount whether the identity is one of Pinot's own service identities (internal calls)
  /// @param claims extra attributes for audit and mapping (token claims, directory attributes); may be empty
  public PinotPrincipal(String user, Set<String> groups, AuthMethod method, boolean serviceAccount,
      Map<String, Object> claims) {
    if (user == null || user.trim().isEmpty()) {
      throw new IllegalArgumentException("Principal user name must not be blank");
    }
    _user = user;
    _groups = Collections.unmodifiableSet(new TreeSet<>(Objects.requireNonNull(groups, "groups")));
    _method = Objects.requireNonNull(method, "method");
    _serviceAccount = serviceAccount;
    _claims = Collections.unmodifiableMap(new LinkedHashMap<>(Objects.requireNonNull(claims, "claims")));
  }

  public String getUser() {
    return _user;
  }

  public Set<String> getGroups() {
    return _groups;
  }

  public AuthMethod getMethod() {
    return _method;
  }

  public boolean isServiceAccount() {
    return _serviceAccount;
  }

  public Map<String, Object> getClaims() {
    return _claims;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof PinotPrincipal)) {
      return false;
    }
    PinotPrincipal that = (PinotPrincipal) o;
    return _serviceAccount == that._serviceAccount && _user.equals(that._user) && _groups.equals(that._groups)
        && _method == that._method && _claims.equals(that._claims);
  }

  @Override
  public int hashCode() {
    return Objects.hash(_user, _groups, _method, _serviceAccount, _claims);
  }

  /// Claims are left out on purpose: they may hold token contents.
  @Override
  public String toString() {
    return "PinotPrincipal{user=" + _user + ", groups=" + _groups + ", method=" + _method.getConfigValue()
        + ", serviceAccount=" + _serviceAccount + "}";
  }
}
