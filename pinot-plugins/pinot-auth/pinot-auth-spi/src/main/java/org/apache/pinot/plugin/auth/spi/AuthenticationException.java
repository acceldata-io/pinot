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

/// Thrown when a request cannot be authenticated: missing credential, a credential of a type the cluster's method does
/// not accept, or a credential the method rejects. Entry points answer it with HTTP 401 (gRPC `UNAUTHENTICATED`) and
/// the `WWW-Authenticate` value from [#getChallenge()]. The message must not contain the credential.
public class AuthenticationException extends RuntimeException {
  private final String _challenge;

  /// @param message reason, safe to log and return
  /// @param challenge value for the `WWW-Authenticate` response header, e.g. `Bearer realm="pinot"`
  public AuthenticationException(String message, String challenge) {
    super(message);
    _challenge = challenge;
  }

  public AuthenticationException(String message, String challenge, Throwable cause) {
    super(message, cause);
    _challenge = challenge;
  }

  /// The `WWW-Authenticate` response header value.
  public String getChallenge() {
    return _challenge;
  }

  /// The challenge for a method: `<scheme> realm="pinot"`.
  public static String challengeFor(AuthMethod method) {
    return method.getScheme() + " realm=\"pinot\"";
  }
}
