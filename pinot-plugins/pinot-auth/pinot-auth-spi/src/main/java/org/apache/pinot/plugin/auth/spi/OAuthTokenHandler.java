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

import javax.annotation.Nullable;


/// Validates incoming bearer tokens for the `oauth2` method. One instance per configured handler; thread-safe after
/// [#init]. Custom handlers implement this interface; keep it stable within a Pinot line.
public interface OAuthTokenHandler extends AutoCloseable {

  void init(HandlerContext context);

  /// @param token the bearer token
  /// @return the identity, or `null` when the token is not meant for this handler (the next handler is tried)
  /// @throws AuthenticationException if the token is invalid or the provider cannot be reached
  @Nullable
  TokenIdentity validate(String token);

  @Override
  default void close() {
  }
}
