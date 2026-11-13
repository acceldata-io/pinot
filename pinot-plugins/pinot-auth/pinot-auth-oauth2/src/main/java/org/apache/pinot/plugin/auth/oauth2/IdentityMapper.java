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
package org.apache.pinot.plugin.auth.oauth2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Turns what a token handler validated into the Pinot principal that authorization sees, so that user and group
/// names match the names used in the authorization rules (native rules, Ranger policies, Ranger UserSync). One mapper
/// per handler, configured under `pinot.auth.oauth2.handler.<name>.`:
///
/// - `user.rules`: ordered rules separated by `;`, each `<regex>/<replacement>/<flags>` with flags `L` (lower-case)
///   or `U` (upper-case), e.g. `^([^@]+)@example\.com$/$1/L`. The first rule whose regex matches the whole name
///   applies. `user.rules.unmatched` = `keep` (default) keeps a name no rule matches, `reject` refuses the token.
/// - `groups.prefix.strip`: comma list of prefixes removed from group names (e.g. `/` for Keycloak group paths,
///   `ROLE_`); `groups.include` / `groups.exclude`: regexes a group must / must not match; `groups.lower` lower-cases
///   group names.
/// - `required.scopes`: comma list of scopes every token must carry; `scopes.as.groups=true` adds `scope:<scope>`
///   groups, so rules can grant by scope.
/// - Service accounts (Pinot's own clients, always authorized): `service.users` (mapped user names) or
///   `service.claim` + `service.claim.values` (e.g. `azp` = the client ids Pinot's components use).
///
/// Immutable and thread-safe.
final class IdentityMapper {
  private final String _handler;
  private final String _challenge;
  private final List<Rule> _userRules;
  private final boolean _rejectUnmatched;
  private final List<String> _groupPrefixes;
  @Nullable
  private final Pattern _groupsInclude;
  @Nullable
  private final Pattern _groupsExclude;
  private final boolean _groupsLower;
  private final Set<String> _requiredScopes;
  private final boolean _scopesAsGroups;
  private final Set<String> _serviceUsers;
  @Nullable
  private final String _serviceClaim;
  private final Set<String> _serviceClaimValues;

  /// One user-name rule.
  private static final class Rule {
    final Pattern _pattern;
    final String _replacement;
    final String _flags;

    Rule(String rule, String handler) {
      // <regex>/<replacement>/<flags>; the regex may contain '/', the last two '/' separate the parts
      int last = rule.lastIndexOf('/');
      int middle = last > 0 ? rule.lastIndexOf('/', last - 1) : -1;
      if (middle <= 0) {
        throw new IllegalArgumentException("Handler " + handler + ": user rule '" + rule
            + "' must be <regex>/<replacement>/<flags>");
      }
      try {
        _pattern = Pattern.compile(rule.substring(0, middle));
      } catch (PatternSyntaxException e) {
        throw new IllegalArgumentException("Handler " + handler + ": invalid regex in user rule '" + rule + "'", e);
      }
      _replacement = rule.substring(middle + 1, last);
      _flags = rule.substring(last + 1).trim().toUpperCase(Locale.ROOT);
      if (!_flags.matches("[LU]?")) {
        throw new IllegalArgumentException("Handler " + handler + ": user rule flags must be L, U or empty, got '"
            + _flags + "'");
      }
    }

    @Nullable
    String apply(String name) {
      Matcher matcher = _pattern.matcher(name);
      if (!matcher.matches()) {
        return null;
      }
      String mapped = matcher.replaceFirst(_replacement);
      if (_flags.equals("L")) {
        return mapped.toLowerCase(Locale.ROOT);
      }
      if (_flags.equals("U")) {
        return mapped.toUpperCase(Locale.ROOT);
      }
      return mapped;
    }
  }

  IdentityMapper(String handler, PinotConfiguration config) {
    _handler = handler;
    _challenge = AuthenticationException.challengeFor(AuthMethod.OAUTH2) + ", error=\"invalid_token\"";
    _userRules = new ArrayList<>();
    String rules = config.getProperty("user.rules");
    if (rules != null) {
      for (String rule : rules.split(";")) {
        if (!rule.trim().isEmpty()) {
          _userRules.add(new Rule(rule.trim(), handler));
        }
      }
    }
    String unmatched = config.getProperty("user.rules.unmatched", "keep").trim();
    if (!unmatched.equals("keep") && !unmatched.equals("reject")) {
      throw new IllegalArgumentException("Handler " + handler + ": user.rules.unmatched must be keep or reject");
    }
    _rejectUnmatched = unmatched.equals("reject");
    _groupPrefixes = new ArrayList<>(csv(config.getProperty("groups.prefix.strip")));
    _groupsInclude = pattern(config.getProperty("groups.include"), "groups.include");
    _groupsExclude = pattern(config.getProperty("groups.exclude"), "groups.exclude");
    _groupsLower = config.getProperty("groups.lower", false);
    _requiredScopes = csv(config.getProperty("required.scopes"));
    _scopesAsGroups = config.getProperty("scopes.as.groups", false);
    _serviceUsers = csv(config.getProperty("service.users"));
    String serviceClaim = config.getProperty("service.claim");
    _serviceClaim = serviceClaim == null || serviceClaim.trim().isEmpty() ? null : serviceClaim.trim();
    _serviceClaimValues = csv(config.getProperty("service.claim.values"));
    if (_serviceClaim != null && _serviceClaimValues.isEmpty()) {
      throw new IllegalArgumentException("Handler " + handler + ": service.claim needs service.claim.values");
    }
  }

  PinotPrincipal map(TokenIdentity identity) {
    for (String scope : _requiredScopes) {
      if (!identity.getScopes().contains(scope)) {
        throw new AuthenticationException("Invalid token (" + _handler + "): missing required scope '" + scope + "'",
            _challenge);
      }
    }
    String user = mapUser(identity.getUser());
    Set<String> groups = new LinkedHashSet<>();
    for (String group : identity.getGroups()) {
      String mapped = mapGroup(group);
      if (mapped != null) {
        groups.add(mapped);
      }
    }
    if (_scopesAsGroups) {
      for (String scope : identity.getScopes()) {
        groups.add("scope:" + scope);
      }
    }
    boolean serviceAccount = _serviceUsers.contains(user) || isServiceClaim(identity.getAttributes());
    Map<String, Object> claims = new LinkedHashMap<>(identity.getAttributes());
    claims.put("handler", _handler);
    if (!user.equals(identity.getUser())) {
      claims.put("token_user", identity.getUser());
    }
    return new PinotPrincipal(user, groups, AuthMethod.OAUTH2, serviceAccount, claims);
  }

  private String mapUser(String name) {
    for (Rule rule : _userRules) {
      String mapped = rule.apply(name);
      if (mapped != null) {
        if (mapped.trim().isEmpty()) {
          throw new AuthenticationException("Invalid token (" + _handler + "): user name maps to an empty name",
              _challenge);
        }
        return mapped;
      }
    }
    if (_rejectUnmatched && !_userRules.isEmpty()) {
      throw new AuthenticationException("Invalid token (" + _handler + "): user name matches no user rule",
          _challenge);
    }
    return name;
  }

  @Nullable
  private String mapGroup(String group) {
    String mapped = group;
    for (String prefix : _groupPrefixes) {
      if (mapped.startsWith(prefix)) {
        mapped = mapped.substring(prefix.length());
        break;
      }
    }
    if (_groupsLower) {
      mapped = mapped.toLowerCase(Locale.ROOT);
    }
    if (mapped.isEmpty()) {
      return null;
    }
    if (_groupsInclude != null && !_groupsInclude.matcher(mapped).matches()) {
      return null;
    }
    if (_groupsExclude != null && _groupsExclude.matcher(mapped).matches()) {
      return null;
    }
    return mapped;
  }

  private boolean isServiceClaim(Map<String, Object> attributes) {
    if (_serviceClaim == null) {
      return false;
    }
    Object value = attributes.get(_serviceClaim);
    if (value instanceof Collection) {
      for (Object item : (Collection<?>) value) {
        if (item != null && _serviceClaimValues.contains(String.valueOf(item))) {
          return true;
        }
      }
      return false;
    }
    return value != null && _serviceClaimValues.contains(String.valueOf(value));
  }

  @Nullable
  private Pattern pattern(@Nullable String regex, String key) {
    if (regex == null || regex.trim().isEmpty()) {
      return null;
    }
    try {
      return Pattern.compile(regex.trim());
    } catch (PatternSyntaxException e) {
      throw new IllegalArgumentException("Handler " + _handler + ": invalid regex in " + key, e);
    }
  }

  private static Set<String> csv(@Nullable String value) {
    Set<String> values = new LinkedHashSet<>();
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
