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
package org.apache.pinot.server.access;

import io.netty.channel.ChannelHandlerContext;
import java.util.Collection;
import javax.annotation.Nullable;
import javax.ws.rs.NotAuthorizedException;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.core.auth.authz.AccessEnforcer;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.auth.AuthorizationResult;
import org.apache.pinot.spi.auth.BasicAuthorizationResultImpl;
import org.apache.pinot.spi.auth.server.RequesterIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Server and Minion access control of the pluggable authentication and authorization framework: the cluster's one
/// authentication method (`pinot.auth.method`) identifies the caller of the admin API and of data access (HTTP and
/// gRPC), and the cluster's one authorizer (`pinot.authz.mode`) decides. Enable with
/// `pinot.server.admin.access.control.factory.class` or `pinot.minion.admin.access.control.factory.class` set to
/// `org.apache.pinot.server.access.PinotAuthAccessFactory`.
///
/// - Admin API: the cluster `ADMIN` permission (access type `manage_cluster_config`). Pinot's own calls use service
///   accounts, which are always allowed.
/// - Data access (segment and valid-doc-id downloads, gRPC queries): `READ` on the table (access type `query`).
/// - Query channels between brokers and servers are secured by TLS, not by this access control.
///
/// A missing or rejected credential raises [NotAuthorizedException] (HTTP 401) with the method's challenge.
public class PinotAuthAccessFactory implements AccessControlFactory {
  private static final String AUTHORIZATION_KEY = "authorization";

  private AccessControl _accessControl;

  @Override
  public void init(PinotConfiguration configuration) {
    // Existing BasicAuth principals (<prefix>.principals) keep their access under the native authorizer
    _accessControl = new PinotAuthAccessControl(AccessEnforcer.create(configuration, "principals"));
  }

  @Override
  public AccessControl create() {
    return _accessControl;
  }

  /// Thread-safe: all state is the thread-safe enforcer.
  static final class PinotAuthAccessControl implements AccessControl {
    private final AccessEnforcer _enforcer;

    PinotAuthAccessControl(AccessEnforcer enforcer) {
      _enforcer = enforcer;
    }

    @Override
    public boolean isAuthorizedChannel(ChannelHandlerContext channelHandlerContext) {
      return true;
    }

    @Override
    public AuthorizationResult authorizeAdminAccess(RequesterIdentity requesterIdentity) {
      PinotPrincipal principal = authenticate(requesterIdentity);
      boolean allowed = _enforcer.isAllowed(principal,
          AccessEnforcer.request(TargetType.CLUSTER, null, null, Permission.ADMIN, "manage_cluster_config"));
      return allowed ? BasicAuthorizationResultImpl.success()
          : new BasicAuthorizationResultImpl(false, "User '" + principal.getUser() + "' may not use the admin API");
    }

    @Override
    public boolean hasDataAccess(RequesterIdentity requesterIdentity, String tableName) {
      return _enforcer.isAllowed(authenticate(requesterIdentity),
          AccessEnforcer.request(TargetType.TABLE, tableName, null, Permission.READ, "query"));
    }

    private PinotPrincipal authenticate(RequesterIdentity requesterIdentity) {
      try {
        return _enforcer.authenticate(authorization(requesterIdentity));
      } catch (AuthenticationException e) {
        throw new NotAuthorizedException(e.getMessage(), e.getChallenge());
      }
    }

    @Nullable
    private static String authorization(RequesterIdentity requesterIdentity) {
      Collection<String> values = null;
      if (requesterIdentity instanceof GrpcRequesterIdentity) {
        values = ((GrpcRequesterIdentity) requesterIdentity).getGrpcMetadata().get(AUTHORIZATION_KEY);
      } else if (requesterIdentity instanceof HttpRequesterIdentity) {
        values = ((HttpRequesterIdentity) requesterIdentity).getHeaderValues(AUTHORIZATION_KEY);
      }
      return values == null || values.isEmpty() ? null : values.iterator().next();
    }
  }
}
