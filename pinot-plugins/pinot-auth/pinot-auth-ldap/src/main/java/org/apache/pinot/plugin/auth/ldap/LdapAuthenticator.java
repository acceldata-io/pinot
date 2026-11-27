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
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;
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
/// - `service.token.alias`: credential store alias of the `Basic` credential Pinot's own calls send (the service
///   account of `service.users` this process signs in as). A sign-in with exactly that user name and password is
///   accepted without asking the directory, so that Pinot's internal calls keep working while the directory is
///   unreachable, also right after a restart when nothing is cached yet. Only for a user listed in `service.users`;
///   any other sign-in, and this user with another password, is checked against the directory as usual.
/// - `required.group`: when set, only members of this group may sign in (compared case-insensitively).
/// - Sign-in caching, the failure cache and the per-user throttle that protects directory accounts from lockout by
///   client retry loops: see [LdapSignInCache].
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
  @Nullable
  private String _requiredGroup;
  private LdapSignInCache _cache;
  /// Pinot's own service account and its password, from `service.token.alias` (null: not set)
  @Nullable
  private String _localServiceUser;
  @Nullable
  private byte[] _localServicePassword;

  @Override
  public AuthMethod getMethod() {
    return AuthMethod.LDAP;
  }

  @Override
  public void init(PinotConfiguration config, SecretResolver secretResolver) {
    init(config, secretResolver, Clock.systemUTC());
  }

  void init(PinotConfiguration config, SecretResolver secretResolver, Clock clock) {
    _cache = new LdapSignInCache(config, clock);
    _directory = new LdapDirectory(config, secretResolver);
    _requiredGroup = LdapDirectory.trimToNull(config.getProperty("required.group"));
    Set<String> serviceUsers = new LinkedHashSet<>();
    for (String user : config.getProperty("service.users", "").split(",")) {
      if (!user.trim().isEmpty()) {
        serviceUsers.add(user.trim());
      }
    }
    _serviceUsers = Set.copyOf(serviceUsers);
    initLocalServiceAccount(config, secretResolver);
    LOGGER.info("LDAP authentication ready: urls={}, bind mode={}, group mode={}, required group={}, service users={}",
        config.getProperty("urls"), _directory.getBindMode(), config.getProperty("group.mode", "none"), _requiredGroup,
        _serviceUsers);
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
        if (password.length == 0) {
          // Refused before the caches too: an empty password never reaches the directory
          throw new LdapDirectory.InvalidCredentialsException("empty password");
        }
        if (isLocalServiceAccount(user, password)) {
          AuthMetrics.mark(METRICS + "serviceLocal");
          return new PinotPrincipal(user, Set.of(), AuthMethod.LDAP, true, Map.of());
        }
        LdapSignInCache.Lookup cached = _cache.lookup(user, password);
        switch (cached._verdict) {
          case CACHED:
            AuthMetrics.mark(METRICS + "cacheHits");
            return principal(cached._user);
          case REPEATED_FAILURE:
            AuthMetrics.mark(METRICS + "rejected");
            throw new AuthenticationException("Invalid user name or password", CHALLENGE);
          case THROTTLED:
            AuthMetrics.mark(METRICS + "throttled");
            LOGGER.warn("LDAP sign-in of '{}' refused without asking the directory: too many wrong passwords recently",
                user);
            throw new AuthenticationException("Invalid user name or password", CHALLENGE);
          default:
            break;
        }
        LdapDirectory.User found;
        try {
          found = _directory.authenticate(user, password);
        } catch (LdapDirectory.InvalidCredentialsException e) {
          _cache.refused(user, password);
          throw e;
        }
        if (_requiredGroup != null && found._groups.stream().noneMatch(_requiredGroup::equalsIgnoreCase)) {
          throw new LdapDirectory.InvalidCredentialsException("not a member of the required group " + _requiredGroup);
        }
        _cache.accepted(user, password, found, _serviceUsers.contains(found._name));
        AuthMetrics.mark(METRICS + "accepted");
        return principal(found);
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

  /// Pinot's own service account from `service.token.alias`: the `Basic` credential this process sends on its
  /// internal calls (with or without the `Basic ` prefix).
  private void initLocalServiceAccount(PinotConfiguration config, SecretResolver secretResolver) {
    String alias = LdapDirectory.trimToNull(config.getProperty("service.token.alias"));
    if (alias == null) {
      return;
    }
    char[] token = secretResolver.resolve(alias);
    try {
      String value = new String(token).trim();
      if (value.regionMatches(true, 0, "Basic ", 0, 6)) {
        value = value.substring(6).trim();
      }
      char[] decoded = decode(value);
      try {
        int colon = indexOf(decoded, ':');
        if (colon <= 0 || colon == decoded.length - 1) {
          throw new IllegalArgumentException("LDAP: the credential under service.token.alias '" + alias
              + "' is not a Basic user:password credential");
        }
        String user = new String(decoded, 0, colon).trim();
        if (!_serviceUsers.contains(user)) {
          throw new IllegalArgumentException("LDAP: the service account of service.token.alias ('" + user
              + "') is not in service.users " + _serviceUsers);
        }
        ByteBuffer encoded =
            StandardCharsets.UTF_8.encode(CharBuffer.wrap(decoded, colon + 1, decoded.length - colon - 1));
        _localServicePassword = new byte[encoded.remaining()];
        encoded.get(_localServicePassword);
        _localServiceUser = user;
      } finally {
        Arrays.fill(decoded, '\0');
      }
    } catch (AuthenticationException e) {
      throw new IllegalArgumentException("LDAP: the credential under service.token.alias '" + alias
          + "' is not a Basic user:password credential");
    } finally {
      Arrays.fill(token, '\0');
    }
  }

  /// The sign-in is Pinot's own service account with the password this process holds (constant-time comparison).
  private boolean isLocalServiceAccount(String user, char[] password) {
    if (_localServiceUser == null || !_localServiceUser.equals(user)) {
      return false;
    }
    ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    byte[] presented = new byte[encoded.remaining()];
    encoded.get(presented);
    try {
      return MessageDigest.isEqual(presented, _localServicePassword);
    } finally {
      Arrays.fill(presented, (byte) 0);
    }
  }

  private PinotPrincipal principal(LdapDirectory.User user) {
    return new PinotPrincipal(user._name, user._groups, AuthMethod.LDAP, _serviceUsers.contains(user._name),
        Map.of("dn", user._dn));
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
