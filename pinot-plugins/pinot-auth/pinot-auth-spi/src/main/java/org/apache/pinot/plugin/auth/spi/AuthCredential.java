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
import javax.annotation.Nullable;


/// A credential from an `Authorization` header (HTTP) or `authorization` metadata (gRPC): the scheme and the value
/// after it, e.g. `Bearer <token>` or `Basic <base64>`. The value is never included in `toString()`.
public final class AuthCredential {
  private final String _scheme;
  private final String _value;

  private AuthCredential(String scheme, String value) {
    _scheme = scheme;
    _value = value;
  }

  /// Parses an `Authorization` header value.
  ///
  /// @return the credential, or `null` when the header is missing, blank or has no value after the scheme
  @Nullable
  public static AuthCredential parse(@Nullable String authorizationHeader) {
    if (authorizationHeader == null) {
      return null;
    }
    String header = authorizationHeader.trim();
    int space = header.indexOf(' ');
    if (space <= 0) {
      return null;
    }
    String value = header.substring(space + 1).trim();
    if (value.isEmpty()) {
      return null;
    }
    return new AuthCredential(header.substring(0, space), value);
  }

  /// The scheme as sent, e.g. `Bearer`.
  public String getScheme() {
    return _scheme;
  }

  /// The credential after the scheme (token, or base64 user:password).
  public String getValue() {
    return _value;
  }

  /// Whether the scheme matches the given one (case-insensitive, as HTTP schemes are).
  public boolean hasScheme(String scheme) {
    return _scheme.toLowerCase(Locale.ROOT).equals(scheme.toLowerCase(Locale.ROOT));
  }

  @Override
  public String toString() {
    return "AuthCredential{scheme=" + _scheme + "}";
  }
}
