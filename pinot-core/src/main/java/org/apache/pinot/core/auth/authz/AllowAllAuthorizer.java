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
package org.apache.pinot.core.auth.authz;

import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.AuthorizationMode;
import org.apache.pinot.plugin.auth.spi.PinotAuthorizer;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;


/// The `none` authorizer (`pinot.authz.mode=none`): authentication without authorization. Every principal the
/// authentication method accepted may do everything, and queries get no row filters. Requests without valid
/// credentials are still refused by the authentication method. Stateless and thread-safe.
public class AllowAllAuthorizer implements PinotAuthorizer {
  private static final AuthorizationDecision ALLOWED = AuthorizationDecision.allow("authorization mode none");

  @Override
  public AuthorizationMode getMode() {
    return AuthorizationMode.NONE;
  }

  @Override
  public void init(PinotConfiguration config) {
  }

  @Override
  public AuthorizationDecision authorize(PinotPrincipal principal, AccessRequest request) {
    return ALLOWED;
  }
}
