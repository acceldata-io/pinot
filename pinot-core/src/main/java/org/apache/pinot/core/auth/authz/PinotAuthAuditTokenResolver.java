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

import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.audit.AuditTokenResolver;
import org.apache.pinot.spi.audit.AuditUserIdentity;


/// Request-audit identity from the authentication and authorization framework: names the user and method that the
/// cluster's authentication method verified for the request's credential, instead of reading an unverified token.
/// Enable with the audit setting `token.resolver.class=org.apache.pinot.core.auth.authz.PinotAuthAuditTokenResolver`.
/// Returns `null` (letting the audit fall back) for a credential this component has not authenticated in the last
/// minutes. Thread-safe.
public class PinotAuthAuditTokenResolver implements AuditTokenResolver {

  @Nullable
  @Override
  public AuditUserIdentity resolve(String authHeaderValue) {
    PinotPrincipal principal = AccessEnforcer.recentPrincipal(authHeaderValue);
    if (principal == null) {
      return null;
    }
    String user = principal.getUser();
    String method = principal.getMethod().getConfigValue();
    return new AuditUserIdentity() {
      @Override
      public String getPrincipal() {
        return user;
      }

      @Override
      public String getAuthMethod() {
        return method;
      }
    };
  }
}
