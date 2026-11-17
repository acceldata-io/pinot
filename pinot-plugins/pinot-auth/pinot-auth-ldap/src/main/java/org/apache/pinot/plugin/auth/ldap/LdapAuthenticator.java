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
package org.apache.pinot.plugin.auth.ldap;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthMetrics;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// The `ldap` authentication method: the user name and password of a `Basic` credential (HTTP header, JDBC
/// properties, CLI, the controller UI's sign-in prompt) are checked against an LDAP or Active Directory server. How the
/// directory is reached and how the password is checked (search-then-bind or direct bind, LDAPS / StartTLS, failover)
/// is described in [LdapDirectory]; all settings are under `pinot.auth.ldap.`.
///
/// - `service.users`: comma-separated user names of Pinot's own directory service accounts (internal calls); their
///   principal is marked as a service account.
///
/// A rejected sign-in answers 401 with `WWW-Authenticate: Basic realm="pinot"`; the reason is logged, never the
/// password. When no directory server answers, the request is refused (never let through). Thread-safe after
/// [#init].
public class LdapAuthenticator implements PinotAuthenticator {
  private static final Logger LOGGER = LoggerFactory.getLogger(LdapAuthenticator.class);
  private static final String CHALLENGE = AuthenticationException.challengeFor(AuthMethod.LDAP);
  static final String METRICS = "ldap.";

  private LdapDirectory _directory;
  private Set<String> _serviceUsers = Set.of();

  @Override
  public AuthMethod getMethod() {
    return AuthMethod.LDAP;
  }

  @Override
  public void init(PinotConfiguration config, SecretResolver secretResolver) {
    _directory = new LdapDirectory(config, secretResolver, new String[]{"1.1"});
    Set<String> serviceUsers = new LinkedHashSet<>();
    for (String user : config.getProperty("service.users", "").split(",")) {
      if (!user.trim().isEmpty()) {
        serviceUsers.add(user.trim());
      }
    }
    _serviceUsers = Set.copyOf(serviceUsers);
    LOGGER.info("LDAP authentication ready: urls={}, bind mode={}, service users={}", config.getProperty("urls"),
        _directory.getBindMode(), _serviceUsers);
  }

  @Override
  public PinotPrincipal authenticate(AuthCredential credential) {
    char[] decoded = decode(credential.getValue());
    try {
      int colon = indexOf(decoded, ':');
      if (colon <= 0) {
        throw reject("malformed Basic credential");
      }
      String user = new String(decoded, 0, colon).trim();
      char[] password = Arrays.copyOfRange(decoded, colon + 1, decoded.length);
      try {
        LdapDirectory.Entry entry = _directory.authenticate(user, password);
        AuthMetrics.mark(METRICS + "accepted");
        return new PinotPrincipal(user, Set.of(), AuthMethod.LDAP, _serviceUsers.contains(user),
            Map.of("dn", entry._dn));
      } catch (LdapDirectory.InvalidCredentialsException e) {
        AuthMetrics.mark(METRICS + "rejected");
        LOGGER.info("LDAP sign-in of '{}' refused: {}", user, e.getMessage());
        throw new AuthenticationException("Invalid user name or password", CHALLENGE);
      } catch (LdapDirectory.DirectoryUnavailableException e) {
        AuthMetrics.mark(METRICS + "unavailable");
        LOGGER.warn("LDAP sign-in of '{}' refused: {}", user, e.getMessage());
        throw new AuthenticationException("Directory unavailable", CHALLENGE);
      } finally {
        Arrays.fill(password, '\0');
      }
    } finally {
      Arrays.fill(decoded, '\0');
    }
  }

  private static AuthenticationException reject(String reason) {
    AuthMetrics.mark(METRICS + "rejected");
    return new AuthenticationException("Invalid user name or password (" + reason + ")", CHALLENGE);
  }

  /// The decoded `user:password`, as characters that can be wiped after use.
  private static char[] decode(String value) {
    byte[] bytes;
    try {
      bytes = Base64.getDecoder().decode(normalizePadding(value.trim()));
    } catch (IllegalArgumentException e) {
      throw reject("malformed Basic credential");
    }
    try {
      CharBuffer chars = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes));
      char[] result = new char[chars.remaining()];
      chars.get(result);
      return result;
    } catch (CharacterCodingException e) {
      throw reject("malformed Basic credential");
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  /// Clients send Basic credentials with missing or extra `=` padding; accept them as BasicAuth does.
  private static String normalizePadding(String value) {
    String stripped = value.replaceAll("=+$", "");
    int padding = (4 - stripped.length() % 4) % 4;
    return padding == 3 ? stripped : stripped + "==".substring(0, padding);
  }

  private static int indexOf(char[] chars, char c) {
    for (int i = 0; i < chars.length; i++) {
      if (chars[i] == c) {
        return i;
      }
    }
    return -1;
  }
}
