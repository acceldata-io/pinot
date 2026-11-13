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
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.core.auth.authz.AccessEnforcer;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthMethodSelector;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.AuthorizerSelector;
import org.apache.pinot.plugin.auth.spi.ConfigSecretResolver;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotAuthorizer;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.tools.AbstractBaseCommand;
import org.apache.pinot.tools.Command;
import picocli.CommandLine;


/// Dry run of the OAuth 2.0 method against a configuration file, without enforcing anything: validates a token with
/// the configured handlers (built-in or custom), and prints the handler settings with secrets masked, the resolved
/// identity after identity mapping and, when tables are given, what the authorizer would decide. Reads the given file,
/// not the cluster, so it can check a pending configuration before the cut-over while the cluster still runs its
/// previous method. The token and secrets are never printed.
@CommandLine.Command(name = "OAuthCheck", mixinStandardHelpOptions = true)
public class OAuthCheckCommand extends AbstractBaseCommand implements Command {
  /// Setting names whose values are never printed.
  private static final Pattern SECRET_KEY =
      Pattern.compile(".*(secret|password|passwd|credential|token\\b|key\\b|apikey).*", Pattern.CASE_INSENSITIVE);
  private static final String MASK = "****";

  @CommandLine.Option(names = {"-configFile"}, required = true,
      description = "Properties file with the pinot.auth.* (and optionally pinot.authz.*) settings to check")
  private String _configFile;

  @CommandLine.Option(names = {"-handler"}, required = false,
      description = "Check only this handler (default: route the token as the cluster would)")
  private String _handler;

  @CommandLine.Option(names = {"-token"}, required = false,
      description = "The token, or '-' to read it from standard input (prefer -tokenFile: shell history)")
  private String _token;

  @CommandLine.Option(names = {"-tokenFile"}, required = false, description = "File holding the token")
  private String _tokenFile;

  @CommandLine.Option(names = {"-tables"}, required = false,
      description = "Comma-separated tables: show whether the identity may query them and read the cluster")
  private String _tables;

  private PrintStream _out = System.out;

  @Override
  public String getName() {
    return "OAuthCheck";
  }

  @Override
  public String description() {
    return "Check a token against the OAuth 2.0 settings of a configuration file, without enforcing anything.";
  }

  public OAuthCheckCommand setConfigFile(String configFile) {
    _configFile = configFile;
    return this;
  }

  public OAuthCheckCommand setHandler(String handler) {
    _handler = handler;
    return this;
  }

  public OAuthCheckCommand setToken(String token) {
    _token = token;
    return this;
  }

  public OAuthCheckCommand setTables(String tables) {
    _tables = tables;
    return this;
  }

  public OAuthCheckCommand setOutput(PrintStream out) {
    _out = out;
    return this;
  }

  @Override
  public boolean execute()
      throws Exception {
    PinotConfiguration config = new PinotConfiguration(readProperties(new File(_configFile)));
    if (_handler != null) {
      config.setProperty(AuthMethodSelector.CONFIG_PREFIX + ".oauth2.handlers", _handler);
    }
    AuthMethod method = AuthMethodSelector.getConfiguredMethod(config);
    if (method != AuthMethod.OAUTH2) {
      _out.println("pinot.auth.method is " + (method == null ? "not set" : method.getConfigValue())
          + "; this check needs oauth2");
      return false;
    }
    String token = readToken();
    printSettings(config);

    PinotPrincipal principal;
    try (PinotAuthenticator authenticator = AuthMethodSelector.create(config, new ConfigSecretResolver(config))) {
      try {
        principal = authenticator.authenticate(AuthCredential.parse("Bearer " + token));
      } catch (AuthenticationException e) {
        _out.println();
        _out.println("Result: REJECTED (HTTP 401): " + mask(e.getMessage(), token));
        return false;
      }
    }
    printIdentity(principal, token);
    if (_tables != null && !_tables.trim().isEmpty()) {
      printAuthorization(config, principal);
    }
    return true;
  }

  private static Map<String, Object> readProperties(File file)
      throws IOException {
    Properties properties = new Properties();
    try (Reader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
      properties.load(reader);
    }
    Map<String, Object> map = new HashMap<>();
    properties.forEach((key, value) -> map.put(key.toString(), value));
    return map;
  }

  private String readToken()
      throws IOException {
    String token = _token;
    if (_tokenFile != null) {
      token = Files.readString(new File(_tokenFile).toPath(), StandardCharsets.UTF_8);
    } else if ("-".equals(token)) {
      token = new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
    }
    if (token == null || token.trim().isEmpty()) {
      throw new IllegalArgumentException("Give the token with -tokenFile, or -token (- for standard input)");
    }
    token = token.trim();
    return token.regionMatches(true, 0, "Bearer ", 0, 7) ? token.substring(7).trim() : token;
  }

  private void printSettings(PinotConfiguration config) {
    PinotConfiguration oauth = AuthMethodSelector.getMethodConfig(config, AuthMethod.OAUTH2);
    _out.println("Method: oauth2, handlers: " + oauth.getProperty("handlers"));
    _out.println("Settings (secrets masked):");
    Map<String, Object> sorted = new TreeMap<>();
    for (String key : oauth.getKeys()) {
      sorted.put(key, oauth.getRawProperty(key, null));
    }
    for (Map.Entry<String, Object> entry : sorted.entrySet()) {
      _out.println("  " + entry.getKey() + " = " + maskSetting(entry.getKey(), String.valueOf(entry.getValue())));
    }
  }

  private void printIdentity(PinotPrincipal principal, String token) {
    _out.println();
    _out.println("Result: ACCEPTED");
    _out.println("  user: " + principal.getUser());
    _out.println("  groups: " + principal.getGroups());
    _out.println("  service account: " + principal.isServiceAccount());
    Object handler = principal.getClaims().get("handler");
    if (handler != null) {
      _out.println("  handler: " + handler);
    }
    _out.println("  claims:");
    for (Map.Entry<String, Object> claim : new TreeMap<>(principal.getClaims()).entrySet()) {
      _out.println("    " + claim.getKey() + " = " + maskSetting(claim.getKey(), mask(String.valueOf(claim.getValue()),
          token)));
    }
  }

  private void printAuthorization(PinotConfiguration config, PinotPrincipal principal) {
    _out.println();
    try (PinotAuthorizer authorizer = AuthorizerSelector.create(config)) {
      _out.println("Authorization (" + authorizer.getMode().getConfigValue() + " mode, as the cluster would decide):");
      if (principal.isServiceAccount()
          || AuthorizerSelector.getServiceAccounts(config).contains(principal.getUser())) {
        _out.println("  service account: every request is allowed");
        return;
      }
      List<AccessRequest> requests = new ArrayList<>();
      for (String table : _tables.split(",")) {
        if (!table.trim().isEmpty()) {
          requests.add(AccessEnforcer.request(TargetType.TABLE, table.trim(), "Query", Permission.READ, "query"));
        }
      }
      requests.add(AccessEnforcer.request(TargetType.CLUSTER, null, null, Permission.READ, "read_metadata"));
      for (AccessRequest request : requests) {
        AuthorizationDecision decision = authorizer.authorize(principal, request);
        _out.println("  " + request + ": " + decision);
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

  /// Removes the token from a text, in case a handler echoed it.
  static String mask(@Nullable String text, String token) {
    return text == null ? "" : text.replace(token, MASK);
  }
}
