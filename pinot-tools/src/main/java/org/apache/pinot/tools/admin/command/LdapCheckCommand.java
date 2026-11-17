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

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
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


/// Dry run of the LDAP / Active Directory method against a configuration file, without enforcing anything: signs a
/// user in with the configured directory settings and prints the settings with secrets masked, the resolved DN, Pinot
/// user name and groups and, when tables are given, what the authorizer (native rules or Ranger) would decide. Reads
/// the given file, not the cluster, so it can check a pending configuration before the cut-over and later serve in the
/// runbook. Run it in the role's environment (e.g. through the start wrapper) when the file names its secrets by
/// environment variable.
///
/// The password is asked for without echo, or read from `-passwordFile` or standard input (`-passwordFile -`); there is
/// no option for it on the command line, where it would land in the shell history and the process list. It is never
/// printed.
@CommandLine.Command(name = "LdapCheck", mixinStandardHelpOptions = true)
public class LdapCheckCommand extends AbstractBaseCommand implements Command {
  @CommandLine.Option(names = {"-configFile"}, required = true,
      description = "Properties file with the pinot.auth.* (and optionally pinot.authz.*) settings to check")
  private String _configFile;

  @CommandLine.Option(names = {"-user"}, required = true, description = "User name to sign in")
  private String _user;

  @CommandLine.Option(names = {"-passwordFile"}, required = false,
      description = "File holding the password, or '-' for standard input (default: asked for without echo)")
  private String _passwordFile;

  @CommandLine.Option(names = {"-tables"}, required = false,
      description = "Comma-separated tables: show whether the user may query them and read the cluster")
  private String _tables;

  private PrintStream _out = System.out;
  private InputStream _in = System.in;

  @Override
  public String getName() {
    return "LdapCheck";
  }

  @Override
  public String description() {
    return "Sign a user in with the LDAP settings of a configuration file, without enforcing anything.";
  }

  public LdapCheckCommand setConfigFile(String configFile) {
    _configFile = configFile;
    return this;
  }

  public LdapCheckCommand setUser(String user) {
    _user = user;
    return this;
  }

  public LdapCheckCommand setPasswordFile(String passwordFile) {
    _passwordFile = passwordFile;
    return this;
  }

  public LdapCheckCommand setTables(String tables) {
    _tables = tables;
    return this;
  }

  public LdapCheckCommand setOutput(PrintStream out) {
    _out = out;
    return this;
  }

  public LdapCheckCommand setInput(InputStream in) {
    _in = in;
    return this;
  }

  @Override
  public boolean execute()
      throws Exception {
    PinotConfiguration config = AuthCheckSupport.readConfiguration(_configFile);
    AuthMethod method = AuthMethodSelector.getConfiguredMethod(config);
    if (method != AuthMethod.LDAP) {
      _out.println("pinot.auth.method is " + (method == null ? "not set" : method.getConfigValue())
          + "; this check needs ldap");
      return false;
    }
    _out.println("Method: ldap");
    AuthCheckSupport.printSettings(config, AuthMethod.LDAP, _out);
    char[] password = readPassword();
    byte[] credential = null;
    PinotPrincipal principal;
    try (PinotAuthenticator authenticator = AuthMethodSelector.create(config, new ConfigSecretResolver(config))) {
      credential = basic(_user, password);
      principal = authenticator.authenticate(AuthCredential.parse("Basic " + new String(credential,
          StandardCharsets.US_ASCII)));
    } catch (AuthenticationException e) {
      _out.println();
      _out.println("Result: REJECTED (HTTP 401): " + e.getMessage()
          + " (the reason is in the log of this command; the directory refused the password, the user was not found "
          + "or is not unique, or no directory server answered)");
      return false;
    } finally {
      Arrays.fill(password, '\0');
      if (credential != null) {
        Arrays.fill(credential, (byte) 0);
      }
    }
    _out.println();
    _out.println("Result: ACCEPTED");
    _out.println("  user: " + principal.getUser());
    _out.println("  groups: " + principal.getGroups());
    _out.println("  service account: " + principal.isServiceAccount());
    for (Map.Entry<String, Object> claim : new TreeMap<>(principal.getClaims()).entrySet()) {
      _out.println("  " + claim.getKey() + ": " + claim.getValue());
    }
    if (_tables != null && !_tables.trim().isEmpty()) {
      AuthCheckSupport.printAuthorization(config, principal, _tables, _out);
    }
    return true;
  }

  private char[] readPassword()
      throws IOException {
    String line;
    if (_passwordFile != null && !_passwordFile.equals("-")) {
      line = Files.readString(Paths.get(_passwordFile), StandardCharsets.UTF_8);
    } else {
      Console console = System.console();
      if (_passwordFile == null && console != null && _in == System.in) {
        char[] typed = console.readPassword("Password of %s: ", _user);
        if (typed == null || typed.length == 0) {
          throw new IllegalArgumentException("No password given");
        }
        return typed;
      }
      line = new BufferedReader(new InputStreamReader(_in, StandardCharsets.UTF_8)).readLine();
    }
    if (line == null) {
      throw new IllegalArgumentException("No password given");
    }
    // A trailing line break (file, echo) is not part of the password
    return line.replaceAll("[\\r\\n]+$", "").toCharArray();
  }

  /// The base64 `user:password` of a Basic credential; intermediate copies of the password are wiped.
  private static byte[] basic(String user, char[] password) {
    byte[] name = (user + ":").getBytes(StandardCharsets.UTF_8);
    ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    byte[] joined = new byte[name.length + encoded.remaining()];
    System.arraycopy(name, 0, joined, 0, name.length);
    encoded.get(joined, name.length, encoded.remaining());
    if (encoded.hasArray()) {
      Arrays.fill(encoded.array(), (byte) 0);
    }
    byte[] result = Base64.getEncoder().encode(joined);
    Arrays.fill(joined, (byte) 0);
    return result;
  }
}
