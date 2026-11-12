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

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;


/// The result of validating a bearer token, before identity mapping turns it into a [PinotPrincipal]. Immutable.
public final class TokenIdentity {
  private final String _user;
  private final Set<String> _groups;
  private final Set<String> _scopes;
  private final Instant _expiresAt;
  private final String _issuer;
  private final Map<String, Object> _attributes;

  public TokenIdentity(String user, Set<String> groups, Set<String> scopes, Instant expiresAt,
      @Nullable String issuer, Map<String, Object> attributes) {
    _user = Objects.requireNonNull(user, "user");
    _groups = Collections.unmodifiableSet(new TreeSet<>(groups));
    _scopes = Collections.unmodifiableSet(new TreeSet<>(scopes));
    _expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
    _issuer = issuer;
    _attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
  }

  public String getUser() {
    return _user;
  }

  public Set<String> getGroups() {
    return _groups;
  }

  public Set<String> getScopes() {
    return _scopes;
  }

  public Instant getExpiresAt() {
    return _expiresAt;
  }

  @Nullable
  public String getIssuer() {
    return _issuer;
  }

  /// Extra claims or response fields, for audit and identity mapping.
  public Map<String, Object> getAttributes() {
    return _attributes;
  }
}
