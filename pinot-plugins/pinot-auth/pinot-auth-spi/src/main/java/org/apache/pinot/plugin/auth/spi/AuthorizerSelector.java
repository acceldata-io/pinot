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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.annotation.Nullable;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.plugin.PluginManager;


/// Selects and creates the one authorizer of a cluster from `pinot.authz.mode`. Only the configured mode's class is
/// loaded: in `ranger` mode the native rules are never read, and a missing Ranger plug-in fails the start instead of
/// silently falling back.
///
/// Settings (the same on every controller, broker, server and Minion):
/// - `pinot.authz.mode` = `native` (default) | `ranger`
/// - `pinot.authz.<mode>.authorizer.class` (optional) overrides the implementation class of the mode
/// - `pinot.authz.<mode>.*` are passed to the authorizer, without the prefix
/// - `pinot.authz.enforce` (default `true`): `false` evaluates and logs every decision but allows all requests, to
///   check rules against real traffic before enforcing them
/// - `pinot.authz.service.accounts`: comma-separated users that Pinot itself uses for calls between its components;
///   they are always allowed, so that ingestion and segment management never depend on the rules
public final class AuthorizerSelector {
  public static final String CONFIG_PREFIX = "pinot.authz";
  public static final String MODE_CONFIG = CONFIG_PREFIX + ".mode";
  public static final String ENFORCE_CONFIG = CONFIG_PREFIX + ".enforce";
  public static final String SERVICE_ACCOUNTS_CONFIG = CONFIG_PREFIX + ".service.accounts";
  public static final String AUTHORIZER_CLASS_SUFFIX = "authorizer.class";

  public static final String DEFAULT_NATIVE_AUTHORIZER = "org.apache.pinot.core.auth.authz.NativeAuthorizer";
  public static final String DEFAULT_RANGER_AUTHORIZER =
      "org.apache.ranger.authorization.pinot.authorizer.RangerPinotAuthorizer";

  private AuthorizerSelector() {
  }

  /// @throws IllegalArgumentException for an unknown value
  public static AuthorizationMode getConfiguredMode(PinotConfiguration config) {
    String value = config.getProperty(MODE_CONFIG);
    return value == null || value.trim().isEmpty() ? AuthorizationMode.NATIVE
        : AuthorizationMode.fromConfigValue(value);
  }

  /// The settings of one mode: `pinot.authz.<mode>.*` without the prefix.
  public static PinotConfiguration getModeConfig(PinotConfiguration config, AuthorizationMode mode) {
    return config.subset(CONFIG_PREFIX + "." + mode.getConfigValue());
  }

  public static boolean isEnforced(PinotConfiguration config) {
    return config.getProperty(ENFORCE_CONFIG, true);
  }

  public static Set<String> getServiceAccounts(PinotConfiguration config) {
    String value = config.getProperty(SERVICE_ACCOUNTS_CONFIG);
    if (value == null) {
      return Collections.emptySet();
    }
    Set<String> users = new LinkedHashSet<>();
    for (String user : value.split(",")) {
      if (!user.trim().isEmpty()) {
        users.add(user.trim());
      }
    }
    return users;
  }

  public static String getAuthorizerClass(PinotConfiguration config, AuthorizationMode mode) {
    String override = getModeConfig(config, mode).getProperty(AUTHORIZER_CLASS_SUFFIX);
    if (override != null && !override.trim().isEmpty()) {
      return override.trim();
    }
    return mode == AuthorizationMode.RANGER ? DEFAULT_RANGER_AUTHORIZER : DEFAULT_NATIVE_AUTHORIZER;
  }

  /// Creates and initializes the authorizer of the configured mode.
  ///
  /// @throws IllegalStateException if the class cannot be created (for `ranger`: the plug-in is not installed), or
  ///     implements another mode than configured
  public static PinotAuthorizer create(PinotConfiguration config) {
    AuthorizationMode mode = getConfiguredMode(config);
    String className = getAuthorizerClass(config, mode);
    PinotAuthorizer authorizer;
    try {
      authorizer = PluginManager.get().createInstance(className);
    } catch (Exception | LinkageError e) {
      throw new IllegalStateException("Cannot create the " + mode.getConfigValue() + " authorizer '" + className
          + "'." + (mode == AuthorizationMode.RANGER ? " Install the Ranger Pinot plug-in or set " + MODE_CONFIG
          + "=native." : ""), e);
    }
    if (authorizer.getMode() != mode) {
      throw new IllegalStateException("Authorizer '" + className + "' implements mode "
          + authorizer.getMode().getConfigValue() + ", but " + MODE_CONFIG + " is " + mode.getConfigValue());
    }
    authorizer.init(getModeConfig(config, mode));
    return authorizer;
  }

  /// Copies the cluster-wide `pinot.auth.*` and `pinot.authz.*` settings of a component's configuration into the
  /// configuration given to its access-control factory, which receives only a subset of the component configuration
  /// on the broker, server and Minion.
  ///
  /// @param factoryConfig the subset given to the factory
  /// @param componentConfig the full component configuration
  /// @return a new configuration with both
  public static PinotConfiguration withClusterAuthSettings(PinotConfiguration factoryConfig,
      @Nullable PinotConfiguration componentConfig) {
    PinotConfiguration merged = factoryConfig.clone();
    if (componentConfig != null) {
      for (String prefix : new String[]{AuthMethodSelector.CONFIG_PREFIX, CONFIG_PREFIX}) {
        PinotConfiguration settings = componentConfig.subset(prefix);
        for (String key : settings.getKeys()) {
          merged.setProperty(prefix + "." + key, settings.getRawProperty(key, null));
        }
      }
    }
    return merged;
  }
}
