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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.util.TreeMap;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthMethodSelector;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.ConfigSecretResolver;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
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
  private static final String MASK = AuthCheckSupport.MASK;

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
    PinotConfiguration config = AuthCheckSupport.readConfiguration(_configFile);
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
      AuthCheckSupport.printAuthorization(config, principal, _tables, _out);
    }
    return true;
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
    AuthCheckSupport.printSettings(config, AuthMethod.OAUTH2, _out);
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

  static String maskSetting(String key, String value) {
    return AuthCheckSupport.maskSetting(key, value);
  }

  /// Removes the token from a text, in case a handler echoed it.
  static String mask(@Nullable String text, String token) {
    return text == null ? "" : text.replace(token, MASK);
  }
}
