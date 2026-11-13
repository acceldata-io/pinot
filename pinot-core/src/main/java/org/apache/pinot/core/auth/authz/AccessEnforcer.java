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

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthMethodSelector;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.AuthorizationMode;
import org.apache.pinot.plugin.auth.spi.AuthorizerSelector;
import org.apache.pinot.plugin.auth.spi.ConfigSecretResolver;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotAuthorizer;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.ResourceType;
import org.apache.pinot.plugin.auth.spi.SingleMethodAuthentication;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.CommonConstants;
import org.apache.pinot.spi.utils.builder.TableNameBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Authentication and authorization for one Pinot component, shared by the controller, broker, server and Minion
/// access controls: the cluster's one authentication method ([AuthMethodSelector], `pinot.auth.*`) identifies the
/// caller, then the cluster's one authorizer ([AuthorizerSelector], `pinot.authz.*`) decides.
///
/// - Service accounts (`pinot.authz.service.accounts`, or principals the method marks as service accounts) are always
///   allowed, so Pinot's own calls between components never depend on the rules.
/// - An action without a mapping in [ActionPermissions] is denied.
/// - An authorizer failure denies the request.
/// - With `pinot.authz.enforce=false` every decision is evaluated and a denial is logged as `would deny`, but the
///   request is allowed.
///
/// Thread-safe.
public final class AccessEnforcer implements AutoCloseable {
  private static final Logger LOGGER = LoggerFactory.getLogger(AccessEnforcer.class);

  private final PinotAuthenticator _authenticator;
  private final SingleMethodAuthentication _authentication;
  private final PinotAuthorizer _authorizer;
  private final boolean _enforce;
  private final Set<String> _serviceAccounts;
  private final Set<String> _unknownActionsReported = ConcurrentHashMap.newKeySet();

  public AccessEnforcer(PinotAuthenticator authenticator, PinotAuthorizer authorizer, boolean enforce,
      Set<String> serviceAccounts) {
    _authenticator = Objects.requireNonNull(authenticator, "authenticator");
    _authentication = new SingleMethodAuthentication(authenticator);
    _authorizer = Objects.requireNonNull(authorizer, "authorizer");
    _enforce = enforce;
    _serviceAccounts = Set.copyOf(serviceAccounts);
  }

  /// Creates the enforcer from a component configuration holding the `pinot.auth.*` and `pinot.authz.*` settings.
  /// Secret aliases of the method are resolved by [ConfigSecretResolver].
  ///
  /// @throws IllegalStateException if `pinot.auth.method` is not set, or the method or authorizer cannot be created
  public static AccessEnforcer create(PinotConfiguration config) {
    return create(config, null);
  }

  /// Like [#create(PinotConfiguration)], and takes over the component's BasicAuth principals, so a BasicAuth cluster
  /// keeps its users and access when it moves to this framework: with the `basic` method they become its principals
  /// (unless `pinot.auth.basic.principals` is set), and in `native` mode they become rules
  /// (`pinot.authz.native.legacy.principals`, passwords left out).
  ///
  /// @param basicAuthPrincipalsPrefix where this component's BasicAuth principals are configured, e.g.
  ///     `controller.admin.access.control.principals`, or `null`
  public static AccessEnforcer create(PinotConfiguration config, @Nullable String basicAuthPrincipalsPrefix) {
    if (basicAuthPrincipalsPrefix != null && config.getProperty(basicAuthPrincipalsPrefix) != null) {
      config = config.clone();
      PinotConfiguration principals = config.subset(basicAuthPrincipalsPrefix);
      String basicTarget = AuthMethodSelector.CONFIG_PREFIX + "." + AuthMethod.BASIC.getConfigValue() + ".principals";
      boolean basicMethod = AuthMethodSelector.getConfiguredMethod(config) == AuthMethod.BASIC;
      if (basicMethod && config.getProperty(basicTarget) == null) {
        copy(config, basicAuthPrincipalsPrefix, principals, basicTarget, true);
      }
      if (AuthorizerSelector.getConfiguredMode(config) == AuthorizationMode.NATIVE) {
        copy(config, basicAuthPrincipalsPrefix, principals,
            AuthorizerSelector.CONFIG_PREFIX + ".native." + NativeAuthorizer.LEGACY_PRINCIPALS, false);
      }
    }
    PinotAuthenticator authenticator = AuthMethodSelector.create(config, new ConfigSecretResolver(config));
    if (authenticator == null) {
      throw new IllegalStateException(AuthMethodSelector.METHOD_CONFIG + " must be set to use this access control");
    }
    PinotAuthorizer authorizer;
    try {
      authorizer = AuthorizerSelector.create(config);
    } catch (RuntimeException e) {
      authenticator.close();
      throw e;
    }
    boolean enforce = AuthorizerSelector.isEnforced(config);
    Set<String> serviceAccounts = AuthorizerSelector.getServiceAccounts(config);
    LOGGER.info("Access enforcement: authentication {}, authorization {}{}, {} service account(s)",
        authenticator.getMethod().getConfigValue(), authorizer.getMode().getConfigValue(),
        enforce ? "" : " in audit-only mode (pinot.authz.enforce=false: denials are logged, not enforced)",
        serviceAccounts.size());
    return new AccessEnforcer(authenticator, authorizer, enforce, serviceAccounts);
  }

  public AuthMethod getMethod() {
    return _authentication.getMethod();
  }

  /// The `WWW-Authenticate` value for this cluster's method.
  public String getChallenge() {
    return _authentication.getChallenge();
  }

  /// @param authorizationHeader value of the `Authorization` header or gRPC metadata entry
  /// @throws AuthenticationException (HTTP 401) when the credential is missing, of another type, or rejected
  public PinotPrincipal authenticate(@Nullable String authorizationHeader) {
    return _authentication.authenticate(authorizationHeader);
  }

  /// Decides a request of an authenticated principal.
  public boolean isAllowed(PinotPrincipal principal, AccessRequest request) {
    if (principal.isServiceAccount() || _serviceAccounts.contains(principal.getUser())) {
      return true;
    }
    AuthorizationDecision decision;
    try {
      decision = _authorizer.authorize(principal, request);
    } catch (RuntimeException e) {
      LOGGER.error("Authorizer failed for user '{}' on {}; denying", principal.getUser(), request, e);
      decision = AuthorizationDecision.deny("authorizer error");
    }
    if (decision.isAllowed()) {
      return true;
    }
    if (!_enforce) {
      LOGGER.warn("Audit-only: would deny user '{}' (groups {}) {}: {}", principal.getUser(), principal.getGroups(),
          request, decision.getReason());
      return true;
    }
    LOGGER.debug("Denied user '{}' (groups {}) {}: {}", principal.getUser(), principal.getGroups(), request,
        decision.getReason());
    return false;
  }

  /// Decides a fine-grained action on a target.
  ///
  /// @param targetId table name (with or without database and type suffix), database name, or ignored for the cluster
  public boolean isAllowed(PinotPrincipal principal, TargetType targetType, @Nullable String targetId,
      String action) {
    ActionPermissions.Requirement requirement = ActionPermissions.get(targetType, action);
    if (requirement == null) {
      if (_unknownActionsReported.add(targetType + ":" + action)) {
        LOGGER.warn("Denying action '{}' on {}: it has no permission mapping", action, targetType);
      }
      return false;
    }
    if (requirement.isAuthenticatedOnly()) {
      return true;
    }
    return isAllowed(principal, request(targetType, targetId, action, requirement.getPermission(),
        requirement.getAccessType()));
  }

  /// Builds a request for a target. A table or database target without a name is a cluster-wide request.
  public static AccessRequest request(TargetType targetType, @Nullable String targetId, @Nullable String action,
      Permission permission, String accessType) {
    if (targetType == TargetType.TABLE && targetId != null && !targetId.isEmpty()) {
      String rawTableName = TableNameBuilder.extractRawTableName(targetId);
      int dot = rawTableName.indexOf('.');
      String database = dot > 0 ? rawTableName.substring(0, dot) : CommonConstants.DEFAULT_DATABASE;
      String table = dot > 0 ? rawTableName.substring(dot + 1) : rawTableName;
      return new AccessRequest(ResourceType.TABLE, database, table, action, permission, accessType);
    }
    if (targetType == TargetType.DATABASE && targetId != null && !targetId.isEmpty()) {
      return new AccessRequest(ResourceType.DATABASE, targetId, null, action, permission, accessType);
    }
    return new AccessRequest(ResourceType.CLUSTER, null, null, action, permission, accessType);
  }

  private static void copy(PinotConfiguration config, String sourcePrefix, PinotConfiguration source, String target,
      boolean withPasswords) {
    config.setProperty(target, config.getProperty(sourcePrefix));
    for (String key : source.getKeys()) {
      if (withPasswords || !key.endsWith(".password")) {
        config.setProperty(target + "." + key, source.getRawProperty(key, null));
      }
    }
  }

  /// Row filters for a principal querying a table: none for service accounts, otherwise the authorizer's. The broker
  /// requires every returned filter.
  ///
  /// @param tableName table name with or without database and type suffix
  public List<String> getRowFilters(PinotPrincipal principal, String tableName) {
    if (principal.isServiceAccount() || _serviceAccounts.contains(principal.getUser())) {
      return List.of();
    }
    AccessRequest table = request(TargetType.TABLE, tableName, null, Permission.READ, "query");
    return _authorizer.getRowFilters(principal, table.getDatabase(), table.getTable());
  }

  public PinotAuthorizer getAuthorizer() {
    return _authorizer;
  }

  @Override
  public void close() {
    try {
      _authorizer.close();
    } finally {
      _authenticator.close();
    }
  }
}
