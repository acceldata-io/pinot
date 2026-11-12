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

/// Obtains tokens for Pinot's own outbound calls under the `oauth2` method (for example client credentials). Callers
/// cache the token and refresh it before expiry. Thread-safe after [#init].
public interface OAuthTokenSource extends AutoCloseable {

  void init(HandlerContext context);

  /// @return a fresh token
  /// @throws IllegalStateException if the provider cannot be reached
  AccessToken fetch();

  @Override
  default void close() {
  }
}
