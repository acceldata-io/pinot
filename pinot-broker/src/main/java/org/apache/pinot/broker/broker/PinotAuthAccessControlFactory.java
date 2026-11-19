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
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.HttpHeaders;
import org.apache.pinot.broker.api.AccessControl;
import org.apache.pinot.common.request.BrokerRequest;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.core.auth.authz.AccessEnforcer;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.AuthorizationMode;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.auth.AuthorizationResult;
import org.apache.pinot.spi.auth.BasicAuthorizationResultImpl;
import org.apache.pinot.spi.auth.TableAuthorizationResult;
import org.apache.pinot.spi.auth.TableRowColAccessResult;
import org.apache.pinot.spi.auth.TableRowColAccessResultImpl;
import org.apache.pinot.spi.auth.broker.RequesterIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.CommonConstants.Broker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Broker access control of the pluggable authentication and authorization framework: the cluster's one
/// authentication method (`pinot.auth.method`) identifies the caller of every query (HTTP and gRPC) and admin call,
/// and the cluster's one authorizer (`pinot.authz.mode`) decides, per table read by a query. Enable with
/// `pinot.broker.access.control.class=org.apache.pinot.broker.broker.PinotAuthAccessControlFactory`.
///
/// A missing or rejected credential raises [NotAuthorizedException] (HTTP 401) with the method's challenge; a table
/// the caller may not query is reported as failed (HTTP 403).
///
/// Row filters are applied by the broker's request handlers only with `pinot.broker.enable.row.column.level.auth`.
/// Without it a table on which the authorizer has row filters for the caller is refused (fail closed): returning its
/// unfiltered rows would ignore the filter.
public class PinotAuthAccessControlFactory extends AccessControlFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(PinotAuthAccessControlFactory.class);

  /// Where the broker's BasicAuth principals are configured, relative to `pinot.broker.access.control`.
  static final String BASIC_AUTH_PRINCIPALS = "principals";

  private AccessControl _accessControl;

  @Override
  public void init(PinotConfiguration configuration) {
    // Existing BasicAuth principals (pinot.broker.access.control.principals) keep their access under the native
    // authorizer
    AccessEnforcer enforcer = AccessEnforcer.create(configuration, BASIC_AUTH_PRINCIPALS);
    boolean rowFiltersApplied = configuration.getProperty(Broker.CONFIG_OF_BROKER_ENABLE_ROW_COLUMN_LEVEL_AUTH,
        Broker.DEFAULT_BROKER_ENABLE_ROW_COLUMN_LEVEL_AUTH);
    if (!rowFiltersApplied && enforcer.getAuthorizer().getMode() != AuthorizationMode.NONE) {
      LOGGER.warn("{} is off: row filters of the {} authorizer cannot be applied, so queries on tables with row "
          + "filters for the caller are refused. Turn it on to let them run filtered.",
          Broker.CONFIG_OF_BROKER_ENABLE_ROW_COLUMN_LEVEL_AUTH, enforcer.getAuthorizer().getMode().getConfigValue());
    }
    _accessControl = new PinotAuthAccessControl(enforcer, rowFiltersApplied);
  }

  @Override
  public AccessControl create() {
    return _accessControl;
  }

  /// Thread-safe: all state is the thread-safe enforcer.
  static final class PinotAuthAccessControl implements AccessControl {
    private static final String QUERY_ACCESS_TYPE = "query";

    private final AccessEnforcer _enforcer;
    private final boolean _rowFiltersApplied;
    // Tables already reported as refused for unapplied row filters (one warning per table, not per query)
    private final Set<String> _reportedUnfilteredTables = ConcurrentHashMap.newKeySet();

    PinotAuthAccessControl(AccessEnforcer enforcer, boolean rowFiltersApplied) {
      _enforcer = enforcer;
      _rowFiltersApplied = rowFiltersApplied;
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
    public boolean hasAccess(@Nullable HttpHeaders httpHeaders, TargetType targetType, String targetId,
        String action) {
      if (httpHeaders == null && targetType == TargetType.TABLE && Actions.Table.QUERY.equals(action)) {
        // A query that did not come over HTTP (gRPC) has no headers here. Its caller and every table it reads were
        // already checked through the requester identity by authorize(identity, tables), with the same requirement
        // as this action (READ, access type query), so there is nothing left to decide.
        return true;
      }
      PinotPrincipal principal = authenticate(authorization(httpHeaders));
      if (targetType == TargetType.TABLE && Actions.Table.QUERY.equals(action) && !rowFiltersAllowQuery(principal,
          targetId)) {
        return false;
      }
      return _enforcer.isAllowed(principal, targetType, targetId, action);
    }

    @Override
    public boolean hasAccess(HttpHeaders httpHeaders, TargetType targetType) {
      authenticate(authorization(httpHeaders));
      return true;
    }

    /// Row filters of the authorizer for the table, applied by the broker when
    /// `pinot.broker.enable.row.column.level.auth` is set.
    @Override
    public TableRowColAccessResult getRowColFilters(RequesterIdentity requesterIdentity, String table) {
      List<String> filters = _enforcer.getRowFilters(authenticate(requesterIdentity), table);
      // A new result per call: the unrestricted instance is shared and must never carry filters
      return filters.isEmpty() ? TableRowColAccessResultImpl.unrestricted() : new TableRowColAccessResultImpl(filters);
    }

    private boolean canQuery(PinotPrincipal principal, String table) {
      return _enforcer.isAllowed(principal,
          AccessEnforcer.request(TargetType.TABLE, table, null, Permission.READ, QUERY_ACCESS_TYPE))
          && rowFiltersAllowQuery(principal, table);
    }

    /// False when the authorizer has row filters for the caller on the table but the broker does not apply them.
    private boolean rowFiltersAllowQuery(PinotPrincipal principal, String table) {
      if (_rowFiltersApplied || _enforcer.getRowFilters(principal, table).isEmpty()) {
        return true;
      }
      if (_reportedUnfilteredTables.add(table)) {
        LOGGER.warn("Refused a query on {} for {}: the authorizer has row filters for it, but {} is off, so the broker "
            + "would return unfiltered rows", table, principal.getUser(),
            Broker.CONFIG_OF_BROKER_ENABLE_ROW_COLUMN_LEVEL_AUTH);
      }
      return false;
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
