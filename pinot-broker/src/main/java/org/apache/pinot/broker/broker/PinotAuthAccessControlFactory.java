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
package org.apache.pinot.broker.broker;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nullable;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.HttpHeaders;
import org.apache.pinot.broker.api.AccessControl;
import org.apache.pinot.common.request.BrokerRequest;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.core.auth.authz.AccessEnforcer;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.auth.AuthorizationResult;
import org.apache.pinot.spi.auth.BasicAuthorizationResultImpl;
import org.apache.pinot.spi.auth.TableAuthorizationResult;
import org.apache.pinot.spi.auth.broker.RequesterIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Broker access control of the pluggable authentication and authorization framework: the cluster's one
/// authentication method (`pinot.auth.method`) identifies the caller of every query (HTTP and gRPC) and admin call,
/// and the cluster's one authorizer (`pinot.authz.mode`) decides, per table read by a query. Enable with
/// `pinot.broker.access.control.class=org.apache.pinot.broker.broker.PinotAuthAccessControlFactory`.
///
/// A missing or rejected credential raises [NotAuthorizedException] (HTTP 401) with the method's challenge; a table
/// the caller may not query is reported as failed (HTTP 403).
public class PinotAuthAccessControlFactory extends AccessControlFactory {
  private AccessControl _accessControl;

  @Override
  public void init(PinotConfiguration configuration) {
    _accessControl = new PinotAuthAccessControl(AccessEnforcer.create(configuration));
  }

  @Override
  public AccessControl create() {
    return _accessControl;
  }

  /// Thread-safe: all state is the thread-safe enforcer.
  static final class PinotAuthAccessControl implements AccessControl {
    private static final String QUERY_ACCESS_TYPE = "query";

    private final AccessEnforcer _enforcer;

    PinotAuthAccessControl(AccessEnforcer enforcer) {
      _enforcer = enforcer;
    }

    /// Entry check of a query: the caller must be authenticated; tables are checked once known.
    @Override
    public AuthorizationResult authorize(RequesterIdentity requesterIdentity) {
      authenticate(requesterIdentity);
      return BasicAuthorizationResultImpl.success();
    }

    @Override
    public AuthorizationResult authorize(RequesterIdentity requesterIdentity, @Nullable BrokerRequest brokerRequest) {
      PinotPrincipal principal = authenticate(requesterIdentity);
      if (brokerRequest == null || !brokerRequest.isSetQuerySource()
          || brokerRequest.getQuerySource().getTableName() == null) {
        return TableAuthorizationResult.success();
      }
      String table = brokerRequest.getQuerySource().getTableName();
      return canQuery(principal, table) ? TableAuthorizationResult.success()
          : new TableAuthorizationResult(Set.of(table));
    }

    @Override
    public TableAuthorizationResult authorize(RequesterIdentity requesterIdentity, Set<String> tables) {
      PinotPrincipal principal = authenticate(requesterIdentity);
      if (tables == null || tables.isEmpty()) {
        return TableAuthorizationResult.success();
      }
      Set<String> failedTables = new HashSet<>();
      for (String table : tables) {
        if (!canQuery(principal, table)) {
          failedTables.add(table);
        }
      }
      return failedTables.isEmpty() ? TableAuthorizationResult.success() : new TableAuthorizationResult(failedTables);
    }

    @Override
    public boolean hasAccess(HttpHeaders httpHeaders, TargetType targetType, String targetId, String action) {
      return _enforcer.isAllowed(authenticate(authorization(httpHeaders)), targetType, targetId, action);
    }

    @Override
    public boolean hasAccess(HttpHeaders httpHeaders, TargetType targetType) {
      authenticate(authorization(httpHeaders));
      return true;
    }

    private boolean canQuery(PinotPrincipal principal, String table) {
      return _enforcer.isAllowed(principal,
          AccessEnforcer.request(TargetType.TABLE, table, null, Permission.READ, QUERY_ACCESS_TYPE));
    }

    private PinotPrincipal authenticate(RequesterIdentity requesterIdentity) {
      Collection<String> values = AccessControlFactory.extractAuthorizationTokens(requesterIdentity);
      return authenticate(values == null || values.isEmpty() ? null : values.iterator().next());
    }

    private PinotPrincipal authenticate(@Nullable String authorization) {
      try {
        return _enforcer.authenticate(authorization);
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
  }
}
