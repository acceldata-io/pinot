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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.AuthorizationMode;
import org.apache.pinot.plugin.auth.spi.AuthorizerSelector;
import org.apache.pinot.plugin.auth.spi.PinotAuthorizer;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// The `ranger` authorizer: every decision and row filter comes from the Apache Ranger plug-in for Pinot, i.e. from the
/// policies of a Ranger service of type `pinot`.
///
/// The plug-in is not built with Pinot: it is installed from Ranger (`ranger-<version>-pinot-plugin`: the jars of its
/// `lib` directory on Pinot's class path, its implementation in `lib/ranger-pinot-plugin-impl` next to them, loaded
/// by Ranger's own class loader). Pinot and the plug-in talk through Ranger's `PinotAccessChecker` contract, which uses
/// only JDK types, so either can be upgraded without rebuilding the other:
/// ```
/// void init(Map<String, String> settings)
/// Map.Entry<Boolean, String> checkAccess(String user, Set<String> groups, String resourceType, String database,
///     String table, String accessType, String action)
/// List<String> getRowFilters(String user, Set<String> groups, String database, String table)
/// void close()
/// ```
/// `resourceType` is the [org.apache.pinot.plugin.auth.spi.ResourceType] name (`CLUSTER`, `DATABASE`, `TABLE`);
/// `accessType` is the Ranger access type Pinot assigns to the request's action (see [ActionPermissions]).
///
/// Settings (`pinot.authz.ranger.*`): `plugin.class` (default [#DEFAULT_PLUGIN_CLASS]); every other setting is passed
/// to the plug-in, e.g. `config.dir` (directory of ranger-pinot-security.xml, ranger-pinot-audit.xml,
/// ranger-policymgr-ssl.xml), `service.name`, `cluster.name`, `cache.ttl.ms`.
///
/// Fails closed: a plug-in error denies the request. Thread-safe after [#init].
public class RangerAuthorizer implements PinotAuthorizer {
  private static final Logger LOGGER = LoggerFactory.getLogger(RangerAuthorizer.class);

  public static final String PLUGIN_CLASS = "plugin.class";
  public static final String DEFAULT_PLUGIN_CLASS = "org.apache.ranger.authorization.pinot.RangerPinotPlugin";

  private Object _plugin;
  private Method _checkAccess;
  private Method _getRowFilters;
  private Method _close;

  @Override
  public AuthorizationMode getMode() {
    return AuthorizationMode.RANGER;
  }

  @Override
  public void init(PinotConfiguration config) {
    String className = config.getProperty(PLUGIN_CLASS, DEFAULT_PLUGIN_CLASS).trim();
    Class<?> pluginClass;
    try {
      pluginClass = Class.forName(className, true, getClass().getClassLoader());
    } catch (ClassNotFoundException | LinkageError e) {
      throw new IllegalStateException("The Ranger plug-in for Pinot is not installed: '" + className
          + "' is not on the class path. Install the Ranger Pinot plug-in (the jars of its lib directory, with lib/"
          + "ranger-pinot-plugin-impl next to them) on every Pinot host, or set " + AuthorizerSelector.MODE_CONFIG
          + "=native.", e);
    }
    Method init;
    try {
      init = pluginClass.getMethod("init", Map.class);
      _checkAccess = pluginClass.getMethod("checkAccess", String.class, Set.class, String.class, String.class,
          String.class, String.class, String.class);
      _getRowFilters = pluginClass.getMethod("getRowFilters", String.class, Set.class, String.class, String.class);
      _close = pluginClass.getMethod("close");
      _plugin = pluginClass.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("'" + className + "' is not a Ranger plug-in for Pinot (PinotAccessChecker): "
          + e.getMessage(), e);
    }

    Map<String, String> settings = new HashMap<>();
    for (String key : config.getKeys()) {
      if (!PLUGIN_CLASS.equals(key) && !AuthorizerSelector.AUTHORIZER_CLASS_SUFFIX.equals(key)) {
        Object value = config.getRawProperty(key, null);
        if (value != null) {
          settings.put(key, String.valueOf(value));
        }
      }
    }
    invoke(init, settings);
    LOGGER.info("Ranger authorization enabled through {} with settings {}", className, settings.keySet());
  }

  @Override
  public AuthorizationDecision authorize(PinotPrincipal principal, AccessRequest request) {
    Object result;
    try {
      result = invoke(_checkAccess, principal.getUser(), principal.getGroups(), request.getResourceType().name(),
          request.getDatabase(), request.getTable(), request.getAccessType(), request.getAction());
    } catch (RuntimeException e) {
      LOGGER.error("Ranger plug-in failed to decide {} for user {}; denying", request, principal.getUser(), e);
      return AuthorizationDecision.deny("Ranger plug-in error: " + e.getClass().getSimpleName());
    }
    if (!(result instanceof Map.Entry)) {
      return AuthorizationDecision.deny("Ranger plug-in returned no decision");
    }
    Map.Entry<?, ?> decision = (Map.Entry<?, ?>) result;
    String reason = String.valueOf(decision.getValue());
    return Boolean.TRUE.equals(decision.getKey()) ? AuthorizationDecision.allow(reason)
        : AuthorizationDecision.deny(reason);
  }

  /// Ranger row filters for the principal on the table. A plug-in error fails the query rather than returning rows
  /// unfiltered.
  @Override
  public List<String> getRowFilters(PinotPrincipal principal, String database, String table) {
    Object result = invoke(_getRowFilters, principal.getUser(), principal.getGroups(), database, table);
    if (result == null) {
      return Collections.emptyList();
    }
    List<String> filters = new ArrayList<>();
    for (Object filter : (List<?>) result) {
      if (filter != null && !filter.toString().trim().isEmpty()) {
        filters.add(filter.toString());
      }
    }
    return filters;
  }

  @Override
  public void close() {
    if (_plugin != null) {
      try {
        invoke(_close);
      } catch (RuntimeException e) {
        LOGGER.warn("Failed to close the Ranger plug-in", e);
      }
    }
  }

  private Object invoke(Method method, Object... args) {
    try {
      return method.invoke(_plugin, args);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      }
      if (cause instanceof Error) {
        throw (Error) cause;
      }
      throw new IllegalStateException(cause);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }
}
