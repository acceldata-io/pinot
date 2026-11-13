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

import java.util.Locale;
import javax.annotation.Nullable;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.plugin.PluginManager;


/// Selects and creates the one authenticator of a cluster from `pinot.auth.method`. Only the configured method's class
/// is loaded and instantiated: there is no chain of methods and no fallback to another method.
///
/// Settings (the same on every controller, broker, server and Minion):
/// - `pinot.auth.method` = `basic` | `oauth2` | `ldap`; unset means the new authentication framework is not in use.
/// - `pinot.auth.<method>.authenticator.class` (optional) overrides the default implementation class of the method.
/// - `pinot.auth.<method>.*` are passed to the authenticator, without the prefix.
public final class AuthMethodSelector {
  public static final String CONFIG_PREFIX = "pinot.auth";
  public static final String METHOD_CONFIG = CONFIG_PREFIX + ".method";
  public static final String AUTHENTICATOR_CLASS_SUFFIX = "authenticator.class";

  /// Default implementation class per method, provided by the method modules.
  public static final String DEFAULT_BASIC_AUTHENTICATOR = "org.apache.pinot.core.auth.authn.BasicAuthenticator";
  public static final String DEFAULT_OAUTH2_AUTHENTICATOR = "org.apache.pinot.plugin.auth.oauth2.OAuth2Authenticator";
  public static final String DEFAULT_LDAP_AUTHENTICATOR = "org.apache.pinot.plugin.auth.ldap.LdapAuthenticator";

  private AuthMethodSelector() {
  }

  /// @return the configured method, or `null` when `pinot.auth.method` is not set
  /// @throws IllegalArgumentException for an unknown value
  @Nullable
  public static AuthMethod getConfiguredMethod(PinotConfiguration config) {
    String value = config.getProperty(METHOD_CONFIG);
    if (value == null || value.trim().isEmpty()) {
      return null;
    }
    return AuthMethod.fromConfigValue(value);
  }

  /// The settings of one method: `pinot.auth.<method>.*` without the prefix.
  public static PinotConfiguration getMethodConfig(PinotConfiguration config, AuthMethod method) {
    return config.subset(CONFIG_PREFIX + "." + method.getConfigValue());
  }

  /// The implementation class name for a method: the override if set, otherwise the default.
  public static String getAuthenticatorClass(PinotConfiguration config, AuthMethod method) {
    String override = getMethodConfig(config, method).getProperty(AUTHENTICATOR_CLASS_SUFFIX);
    if (override != null && !override.trim().isEmpty()) {
      return override.trim();
    }
    switch (method) {
      case BASIC:
        return DEFAULT_BASIC_AUTHENTICATOR;
      case OAUTH2:
        return DEFAULT_OAUTH2_AUTHENTICATOR;
      case LDAP:
        return DEFAULT_LDAP_AUTHENTICATOR;
      default:
        throw new IllegalStateException("No authenticator for method " + method);
    }
  }

  /// Creates and initializes the authenticator of the configured method.
  ///
  /// @return the authenticator, or `null` when `pinot.auth.method` is not set
  /// @throws IllegalStateException if the class cannot be created, or implements another method than configured
  @Nullable
  public static PinotAuthenticator create(PinotConfiguration config, SecretResolver secretResolver) {
    AuthMethod method = getConfiguredMethod(config);
    if (method == null) {
      return null;
    }
    String className = getAuthenticatorClass(config, method);
    PinotAuthenticator authenticator;
    try {
      authenticator = PluginManager.get().createInstance(className);
    } catch (Exception e) {
      throw new IllegalStateException("Cannot create the " + method.getConfigValue() + " authenticator '" + className
          + "'. Check that its module is installed.", e);
    }
    if (authenticator.getMethod() != method) {
      throw new IllegalStateException("Authenticator '" + className + "' implements method "
          + authenticator.getMethod().getConfigValue() + ", but " + METHOD_CONFIG + " is " + method.getConfigValue());
    }
    authenticator.init(getMethodConfig(config, method), secretResolver);
    return authenticator;
  }

  /// Lower-case name used in log and error messages.
  static String describe(AuthMethod method) {
    return method.getConfigValue().toLowerCase(Locale.ROOT);
  }
}
