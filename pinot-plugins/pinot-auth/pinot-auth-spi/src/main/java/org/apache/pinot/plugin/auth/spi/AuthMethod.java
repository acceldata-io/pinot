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


/// The authentication method of a cluster. Exactly one method is configured per cluster (`pinot.auth.method`) and
/// used by every controller, broker, server and Minion, for users and for Pinot's own internal calls. Methods are never
/// combined: a credential of another type is rejected.
public enum AuthMethod {
  /// User name and password checked against principals configured in Pinot.
  BASIC("basic", "Basic"),
  /// OAuth 2.0 / OpenID Connect bearer tokens.
  OAUTH2("oauth2", "Bearer"),
  /// User name and password checked against an LDAP or Active Directory server.
  LDAP("ldap", "Basic");

  private final String _configValue;
  private final String _scheme;

  AuthMethod(String configValue, String scheme) {
    _configValue = configValue;
    _scheme = scheme;
  }

  /// The value used for this method in `pinot.auth.method`.
  public String getConfigValue() {
    return _configValue;
  }

  /// The HTTP authentication scheme this method accepts (`Authorization: <scheme> ...`), also used in the
  /// `WWW-Authenticate` challenge.
  public String getScheme() {
    return _scheme;
  }

  /// Parses a `pinot.auth.method` value (case-insensitive, surrounding spaces ignored).
  ///
  /// @throws IllegalArgumentException for an unknown value
  public static AuthMethod fromConfigValue(String value) {
    String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    for (AuthMethod method : values()) {
      if (method._configValue.equals(normalized)) {
        return method;
      }
    }
    throw new IllegalArgumentException("Unknown authentication method '" + value + "'; expected one of basic, oauth2, "
        + "ldap");
  }
}
