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

import org.apache.pinot.spi.env.PinotConfiguration;


/// Authenticates requests for one authentication method. A cluster runs exactly one implementation, selected by
/// `pinot.auth.method` (see [AuthMethodSelector]). Implementations need a public no-argument constructor and must be
/// thread-safe after [#init].
///
/// [SingleMethodAuthentication] calls [#authenticate] only with a credential whose scheme matches [#getMethod()]; other
/// credential types are rejected before reaching the implementation.
public interface PinotAuthenticator extends AutoCloseable {

  /// The method this authenticator implements; must equal the configured method.
  AuthMethod getMethod();

  /// Initializes the authenticator.
  ///
  /// @param config the method's own settings, i.e. the subset `pinot.auth.<method>.*` with the prefix removed
  /// @param secretResolver resolves secrets referenced by alias in the settings
  void init(PinotConfiguration config, SecretResolver secretResolver);

  /// Authenticates a credential of this method's scheme.
  ///
  /// @return the principal
  /// @throws AuthenticationException if the credential is invalid or cannot be checked (for example the identity
  ///     provider is unreachable); never returns `null`
  PinotPrincipal authenticate(AuthCredential credential);

  @Override
  default void close() {
  }
}
