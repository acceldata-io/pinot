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
import javax.annotation.Nullable;


/// Applies the cluster's one authentication method to a request credential. A missing credential, or one of another
/// type than the method accepts (for example BasicAuth on an OAuth cluster), is rejected with an
/// [AuthenticationException] carrying the method's challenge, before the authenticator sees it. Thread-safe.
public final class SingleMethodAuthentication {
  private final PinotAuthenticator _authenticator;
  private final AuthMethod _method;
  private final String _challenge;

  public SingleMethodAuthentication(PinotAuthenticator authenticator) {
    _authenticator = Objects.requireNonNull(authenticator, "authenticator");
    _method = authenticator.getMethod();
    _challenge = AuthenticationException.challengeFor(_method);
  }

  public AuthMethod getMethod() {
    return _method;
  }

  /// The `WWW-Authenticate` value for this cluster's method.
  public String getChallenge() {
    return _challenge;
  }

  /// Authenticates the value of an `Authorization` header.
  ///
  /// @throws AuthenticationException (HTTP 401) when the credential is missing, of another type, or rejected
  public PinotPrincipal authenticate(@Nullable String authorizationHeader) {
    AuthCredential credential = AuthCredential.parse(authorizationHeader);
    if (credential == null) {
      throw new AuthenticationException("Missing credential; this cluster accepts " + _method.getScheme()
          + " credentials", _challenge);
    }
    if (!credential.hasScheme(_method.getScheme())) {
      throw new AuthenticationException("Credential type '" + credential.getScheme() + "' is not accepted; this "
          + "cluster uses " + AuthMethodSelector.describe(_method) + " authentication (" + _method.getScheme() + ")",
          _challenge);
    }
    PinotPrincipal principal = _authenticator.authenticate(credential);
    if (principal == null) {
      throw new AuthenticationException("Credential rejected", _challenge);
    }
    if (principal.getMethod() != _method) {
      throw new IllegalStateException("Authenticator for " + AuthMethodSelector.describe(_method)
          + " returned a principal of method " + AuthMethodSelector.describe(principal.getMethod()));
    }
    return principal;
  }
}
