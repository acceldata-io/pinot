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
package org.apache.pinot.tools.admin.command;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.core.auth.authz.AccessEnforcer;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthMethodSelector;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.AuthorizerSelector;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotAuthorizer;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.tools.utils.PinotConfigUtils;


/// Shared parts of the authentication dry-run commands ([OAuthCheckCommand], [LdapCheckCommand]): reading the
/// configuration file, printing a method's settings with secrets masked, and what the authorizer would decide.
final class AuthCheckSupport {
  /// Setting names whose values are never printed.
  private static final Pattern SECRET_KEY =
      Pattern.compile(".*(secret|password|passwd|credential|token\\b|key\\b|apikey).*", Pattern.CASE_INSENSITIVE);
  static final String MASK = "****";

  private AuthCheckSupport() {
  }

  /// The properties of a configuration file, read as the Pinot roles read theirs
  /// ([PinotConfigUtils#readConfigFromFile]), so the check sees the same values as the cluster (e.g. `\2C` in a DN
  /// stays as written, which `java.util.Properties` would turn into `2C`). Pinot's dynamic configuration (e.g.
  /// `dynamic.env.config`) applies, so a role's file read in the role's environment resolves its secrets as the role
  /// does.
  static PinotConfiguration readConfiguration(String file)
      throws IOException {
    if (!new File(file).isFile()) {
      throw new IOException("Configuration file not found: " + file);
    }
    try {
      return new PinotConfiguration(PinotConfigUtils.readConfigFromFile(file));
    } catch (ConfigurationException e) {
      throw new IOException("Cannot read configuration file " + file + ": " + e.getMessage(), e);
    }
  }

  /// The method's settings (`pinot.auth.<method>.*`), secrets masked.
  static void printSettings(PinotConfiguration config, AuthMethod method, PrintStream out) {
    PinotConfiguration settings = AuthMethodSelector.getMethodConfig(config, method);
    out.println("Settings of pinot.auth." + method.getConfigValue() + " (secrets masked):");
    Map<String, Object> sorted = new TreeMap<>();
    for (String key : settings.getKeys()) {
      // As the method reads it: a value with commas (e.g. a DN) is one string, not a list
      sorted.put(key, settings.getProperty(key));
    }
    for (Map.Entry<String, Object> entry : sorted.entrySet()) {
      out.println("  " + entry.getKey() + " = " + maskSetting(entry.getKey(), String.valueOf(entry.getValue())));
    }
  }

  /// What the configured authorizer would decide for the principal: a query of each table and a cluster-wide read.
  static void printAuthorization(PinotConfiguration config, PinotPrincipal principal, String tables, PrintStream out) {
    out.println();
    try (PinotAuthorizer authorizer = AuthorizerSelector.create(config)) {
      out.println("Authorization (" + authorizer.getMode().getConfigValue() + " mode, as the cluster would decide):");
      if (principal.isServiceAccount()
          || AuthorizerSelector.getServiceAccounts(config).contains(principal.getUser())) {
        out.println("  service account: every request is allowed");
        return;
      }
      List<AccessRequest> requests = new ArrayList<>();
      for (String table : tables.split(",")) {
        if (!table.trim().isEmpty()) {
          requests.add(AccessEnforcer.request(TargetType.TABLE, table.trim(), "Query", Permission.READ, "query"));
        }
      }
      requests.add(AccessEnforcer.request(TargetType.CLUSTER, null, null, Permission.READ, "read_metadata"));
      for (AccessRequest request : requests) {
        AuthorizationDecision decision = authorizer.authorize(principal, request);
        out.println("  " + request + ": " + decision);
      }
    }
  }

  static String maskSetting(String key, String value) {
    if (key.startsWith("secrets.") || key.contains(".secrets.")
        || (SECRET_KEY.matcher(key).matches() && !key.endsWith(".alias") && !key.endsWith("alias"))) {
      return MASK;
    }
    return value;
  }
}
