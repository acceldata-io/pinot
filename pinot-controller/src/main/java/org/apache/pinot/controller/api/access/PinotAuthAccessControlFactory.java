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
package org.apache.pinot.controller.api.access;

import java.util.List;
import javax.annotation.Nullable;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.HttpHeaders;
import org.apache.pinot.controller.helix.core.PinotHelixResourceManager;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.core.auth.authz.AccessEnforcer;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Controller access control of the pluggable authentication and authorization framework: the cluster's one
/// authentication method (`pinot.auth.method`) identifies the caller and the cluster's one authorizer
/// (`pinot.authz.mode`) decides every request. Enable by setting `controller.admin.access.control.factory.class` to
/// `org.apache.pinot.controller.api.access.PinotAuthAccessControlFactory`.
///
/// Requests that name no table are cluster-wide and are authorized on the cluster resource, so a principal limited to
/// some tables cannot reach cluster state (apache/pinot#14595). A missing or rejected credential is answered with
/// HTTP 401 and the method's challenge; a denied request with 403.
public class PinotAuthAccessControlFactory implements AccessControlFactory {
  /// Where the controller's BasicAuth principals are configured.
  static final String BASIC_AUTH_PRINCIPALS = "controller.admin.access.control.principals";

  private AccessControl _accessControl;

  @Override
  public void init(PinotConfiguration configuration) {
    // Existing BasicAuth principals keep their access under the native authorizer
    _accessControl = new PinotAuthAccessControl(AccessEnforcer.create(configuration, BASIC_AUTH_PRINCIPALS));
  }

  @Override
  public void init(PinotConfiguration configuration, PinotHelixResourceManager helixResourceManager) {
    init(configuration);
  }

  @Override
  public AccessControl create() {
    return _accessControl;
  }

  /// Thread-safe: all state is the thread-safe enforcer.
  static final class PinotAuthAccessControl implements AccessControl {
    private static final String HEADER_AUTHORIZATION = "Authorization";

    private final AccessEnforcer _enforcer;

    PinotAuthAccessControl(AccessEnforcer enforcer) {
      _enforcer = enforcer;
    }

    @Override
    public boolean protectAnnotatedOnly() {
      return false;
    }

    @Override
    public boolean hasAccess(@Nullable String tableName, AccessType accessType, HttpHeaders httpHeaders,
        String endpointUrl) {
      if (tableName == null) {
        // The request names no table, so it is cluster-wide
        return hasAccess(accessType, httpHeaders, endpointUrl);
      }
      return _enforcer.isAllowed(authenticate(httpHeaders),
          AccessEnforcer.request(TargetType.TABLE, tableName, null, permission(accessType), accessType(accessType)));
    }

    @Override
    public boolean hasAccess(AccessType accessType, HttpHeaders httpHeaders, String endpointUrl) {
      return _enforcer.isAllowed(authenticate(httpHeaders),
          AccessEnforcer.request(TargetType.CLUSTER, null, null, permission(accessType), accessType(accessType)));
    }

    @Override
    public boolean hasAccess(HttpHeaders httpHeaders, TargetType targetType, String targetId, String action) {
      return _enforcer.isAllowed(authenticate(httpHeaders), targetType, targetId, action);
    }

    /// Backs the UI sign-in check (`auth/verify/v2`): whether the credential is valid, not what it may do.
    @Override
    public boolean hasAccess(HttpHeaders httpHeaders, TargetType targetType) {
      try {
        _enforcer.authenticate(authorization(httpHeaders));
        return true;
      } catch (AuthenticationException e) {
        return false;
      }
    }

    /// The UI prompts for a user and password only for password methods; with OAuth 2.0 the token comes from an
    /// authenticating proxy in front of the UI.
    @Override
    public AuthWorkflowInfo getAuthWorkflowInfo() {
      return new AuthWorkflowInfo(
          _enforcer.getMethod() == AuthMethod.OAUTH2 ? AccessControl.WORKFLOW_NONE : AccessControl.WORKFLOW_BASIC);
    }

    private PinotPrincipal authenticate(@Nullable HttpHeaders httpHeaders) {
      try {
        return _enforcer.authenticate(authorization(httpHeaders));
      } catch (AuthenticationException e) {
        throw new NotAuthorizedException(e.getMessage(), e.getChallenge());
      }
    }

    @Nullable
    private static String authorization(@Nullable HttpHeaders httpHeaders) {
      if (httpHeaders == null) {
        return null;
      }
      List<String> values = httpHeaders.getRequestHeader(HEADER_AUTHORIZATION);
      return values == null || values.isEmpty() ? null : values.get(0);
    }

    private static Permission permission(AccessType accessType) {
      return Permission.fromName(accessType.name());
    }

    /// Coarse checks of endpoints without a fine-grained action: reads are metadata reads, changes manage tables.
    private static String accessType(AccessType accessType) {
      return accessType == AccessType.READ ? "read_metadata" : "manage_table";
    }
  }
}
