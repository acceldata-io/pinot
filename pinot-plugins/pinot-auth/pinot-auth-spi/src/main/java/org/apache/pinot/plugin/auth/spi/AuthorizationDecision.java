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


/// An authorizer's answer with the reason (matching rule or policy, or why nothing matched), for logs and audit.
/// Immutable.
public final class AuthorizationDecision {
  private final boolean _allowed;
  private final String _reason;

  private AuthorizationDecision(boolean allowed, String reason) {
    _allowed = allowed;
    _reason = Objects.requireNonNull(reason, "reason");
  }

  public static AuthorizationDecision allow(String reason) {
    return new AuthorizationDecision(true, reason);
  }

  public static AuthorizationDecision deny(String reason) {
    return new AuthorizationDecision(false, reason);
  }

  public boolean isAllowed() {
    return _allowed;
  }

  public String getReason() {
    return _reason;
  }

  @Override
  public String toString() {
    return (_allowed ? "allowed" : "denied") + " (" + _reason + ")";
  }
}
