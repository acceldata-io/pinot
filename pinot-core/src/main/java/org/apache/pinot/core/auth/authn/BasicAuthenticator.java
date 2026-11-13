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
package org.apache.pinot.core.auth.authn;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;
import org.apache.pinot.common.auth.BasicAuthTokenUtils;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;


/// The `basic` authentication method: user name and password checked against principals in Pinot's configuration,
/// the same principals BasicAuth uses today.
///
/// Settings (under `pinot.auth.basic.`):
/// - `principals`: comma-separated user names
/// - `principals.<user>.password`, or `principals.<user>.password.alias` to read it from the secret resolver
/// - `principals.<user>.groups` (optional): groups for authorization rules
/// - `principals.<user>.service.account=true` (optional): Pinot's own service user, always authorized
///
/// Passwords are compared in constant time over their SHA-256 digests. Thread-safe after [#init].
public class BasicAuthenticator implements PinotAuthenticator {
  private static final String CHALLENGE = AuthenticationException.challengeFor(AuthMethod.BASIC);

  private Map<String, Account> _accounts = Collections.emptyMap();

  private static final class Account {
    final byte[] _passwordDigest;
    final Set<String> _groups;
    final boolean _serviceAccount;

    Account(byte[] passwordDigest, Set<String> groups, boolean serviceAccount) {
      _passwordDigest = passwordDigest;
      _groups = groups;
      _serviceAccount = serviceAccount;
    }
  }

  @Override
  public AuthMethod getMethod() {
    return AuthMethod.BASIC;
  }

  @Override
  public void init(PinotConfiguration config, SecretResolver secretResolver) {
    Map<String, Account> accounts = new HashMap<>();
    PinotConfiguration principals = config.subset("principals");
    for (String user : list(config.getProperty("principals"))) {
      PinotConfiguration principal = principals.subset(user);
      String password = principal.getProperty("password");
      String alias = principal.getProperty("password.alias");
      if (alias != null && !alias.trim().isEmpty()) {
        password = new String(secretResolver.resolve(alias.trim()));
      }
      if (password == null || password.isEmpty()) {
        throw new IllegalArgumentException("Basic principal '" + user + "' has no password");
      }
      accounts.put(user, new Account(digest(password), new LinkedHashSet<>(list(principal.getProperty("groups"))),
          principal.getProperty("service.account", false)));
    }
    if (accounts.isEmpty()) {
      throw new IllegalArgumentException("pinot.auth.basic.principals must name at least one user");
    }
    _accounts = Map.copyOf(accounts);
  }

  @Override
  public PinotPrincipal authenticate(AuthCredential credential) {
    String decoded;
    try {
      // Padding is normalized as BasicAuth does, so clients that send extra or no '=' keep working
      decoded = new String(Base64.getDecoder().decode(BasicAuthTokenUtils.normalizeBase64Token(credential.getValue())),
          StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      throw new AuthenticationException("Malformed Basic credential", CHALLENGE);
    }
    int colon = decoded.indexOf(':');
    if (colon <= 0) {
      throw new AuthenticationException("Malformed Basic credential", CHALLENGE);
    }
    String user = decoded.substring(0, colon);
    Account account = _accounts.get(user);
    // Compare even for an unknown user, so the answer time does not reveal which users exist
    byte[] given = digest(decoded.substring(colon + 1));
    boolean matches = MessageDigest.isEqual(given, account != null ? account._passwordDigest : new byte[given.length]);
    if (account == null || !matches) {
      throw new AuthenticationException("Invalid user name or password", CHALLENGE);
    }
    return new PinotPrincipal(user, account._groups, AuthMethod.BASIC, account._serviceAccount, Map.of());
  }

  private static byte[] digest(String password) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static List<String> list(@Nullable String value) {
    List<String> values = new ArrayList<>();
    if (value != null) {
      for (String part : value.split(",")) {
        if (!part.trim().isEmpty()) {
          values.add(part.trim());
        }
      }
    }
    return values;
  }
}
