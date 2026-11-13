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
package org.apache.pinot.core.auth.authz;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.AuthorizationMode;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotAuthorizer;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.CommonConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// The `native` authorizer: rules in Pinot's own configuration. A request is allowed if any rule for the user or one
/// of the user's groups allows it; otherwise it is denied.
///
/// Rules (under `pinot.authz.native.`):
/// ```
/// rules=analysts,ingest,admins
/// rule.analysts.groups=pinot-analysts
/// rule.analysts.permissions=READ
/// rule.analysts.tables=orders,orders_*,fin.*
/// rule.analysts.rowFilter.orders=region = 'south'
/// rule.ingest.users=svc-pinot-ci
/// rule.ingest.permissions=READ,CREATE,UPDATE
/// rule.ingest.tables=fin.*
/// rule.ingest.excludeTables=fin.audit
/// rule.admins.groups=pinot-admins
/// rule.admins.permissions=ALL
/// rule.admins.tables=*
/// ```
/// - `users` / `groups`: who the rule is for (at least one); groups come from the authentication method.
/// - `permissions`: `READ`, `CREATE`, `UPDATE`, `DELETE`, `ADMIN`, `ALL`.
/// - `tables` (required) and `excludeTables`: table names or globs (`*`, `?`), matched against `<database>.<table>`
///   and, for the default database, also against the plain table name.
/// - A request that names no table is cluster-wide and needs a rule with `tables=*` and no `excludeTables`, so a
///   principal limited to some tables cannot reach cluster state (apache/pinot#14595). A database-level request needs
///   `*` or `<database>.*` without `excludeTables`.
/// - `rowFilter.<table>`: a predicate the broker adds to queries of that table for this rule. A principal granted
///   `READ` by several rules sees the rows of any of them (the filters are OR-ed); a granting rule without a filter
///   means all rows.
///
/// BasicAuth principals (`legacy.principals`, passed here by the access controls from their BasicAuth settings, e.g.
/// `controller.admin.access.control.principals`) are read as one rule each, so a BasicAuth cluster keeps its access
/// when it moves to this authorizer: no `permissions` means `ALL`, no `tables` means `*`, `<table>.rls` filters are
/// kept. Passwords are ignored: authentication belongs to the method.
///
/// Every rule is validated at start: an unknown permission, a rule without users and groups, a rule without tables or
/// a malformed table pattern fails the start. Immutable and thread-safe after [#init].
public class NativeAuthorizer implements PinotAuthorizer {
  private static final Logger LOGGER = LoggerFactory.getLogger(NativeAuthorizer.class);
  private static final Pattern VALID_TABLE_PATTERN = Pattern.compile("[A-Za-z0-9_\\-.*?]+");
  private static final String ALL_TABLES = "*";
  /// Settings key of the BasicAuth principals read as rules.
  public static final String LEGACY_PRINCIPALS = "legacy.principals";

  private List<Rule> _rules = Collections.emptyList();

  /// One rule. Immutable.
  private static final class Rule {
    final String _name;
    final Set<String> _users;
    final Set<String> _groups;
    final Set<Permission> _permissions;
    final List<String> _tables;
    final List<Pattern> _tablePatterns;
    final List<String> _excludeTables;
    final List<Pattern> _excludePatterns;
    /// Row filter settings: `rowFilter.<table>` (native) or `<table>.rls` (legacy, comma-separated).
    final PinotConfiguration _filterConfig;
    final boolean _legacy;

    Rule(String name, Set<String> users, Set<String> groups, Set<Permission> permissions, List<String> tables,
        List<String> excludeTables, PinotConfiguration filterConfig, boolean legacy) {
      if (users.isEmpty() && groups.isEmpty()) {
        throw new IllegalArgumentException("Rule '" + name + "' names no users and no groups");
      }
      if (permissions.isEmpty()) {
        throw new IllegalArgumentException("Rule '" + name + "' grants no permissions");
      }
      if (tables.isEmpty()) {
        throw new IllegalArgumentException("Rule '" + name + "' names no tables (use * for all tables)");
      }
      _name = name;
      _users = users;
      _groups = groups;
      _permissions = permissions;
      _tables = tables;
      _tablePatterns = compile(name, tables);
      _excludeTables = excludeTables;
      _excludePatterns = compile(name, excludeTables);
      _filterConfig = filterConfig;
      _legacy = legacy;
    }

    boolean appliesTo(PinotPrincipal principal) {
      if (_users.contains(principal.getUser())) {
        return true;
      }
      for (String group : principal.getGroups()) {
        if (_groups.contains(group)) {
          return true;
        }
      }
      return false;
    }

    boolean grants(Permission permission) {
      for (Permission granted : _permissions) {
        if (granted.grants(permission)) {
          return true;
        }
      }
      return false;
    }

    boolean coversCluster() {
      return _tables.contains(ALL_TABLES) && _excludeTables.isEmpty();
    }

    boolean coversDatabase(String database) {
      return _excludeTables.isEmpty() && (_tables.contains(ALL_TABLES) || _tables.contains(database + ".*"));
    }

    boolean coversTable(String database, String table) {
      return matchesAny(_tablePatterns, database, table) && !matchesAny(_excludePatterns, database, table);
    }

    /// @return the filters of this rule for the table, empty for all rows
    List<String> rowFilters(String database, String table) {
      List<String> keys = new ArrayList<>();
      keys.add(database + "." + table);
      if (database.equals(CommonConstants.DEFAULT_DATABASE)) {
        keys.add(table);
      }
      for (String key : keys) {
        String value = _filterConfig.getProperty(_legacy ? key + ".rls" : key);
        if (value != null && !value.trim().isEmpty()) {
          if (!_legacy) {
            return List.of(value.trim());
          }
          return Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty())
              .collect(Collectors.toList());
        }
      }
      return Collections.emptyList();
    }

    private static boolean matchesAny(List<Pattern> patterns, String database, String table) {
      String qualified = database + "." + table;
      boolean defaultDatabase = database.equals(CommonConstants.DEFAULT_DATABASE);
      for (Pattern pattern : patterns) {
        if (pattern.matcher(qualified).matches() || (defaultDatabase && pattern.matcher(table).matches())) {
          return true;
        }
      }
      return false;
    }

    private static List<Pattern> compile(String rule, List<String> globs) {
      List<Pattern> patterns = new ArrayList<>();
      for (String glob : globs) {
        if (!VALID_TABLE_PATTERN.matcher(glob).matches()) {
          throw new IllegalArgumentException("Rule '" + rule + "': invalid table pattern '" + glob + "'");
        }
        StringBuilder regex = new StringBuilder();
        for (char c : glob.toCharArray()) {
          if (c == '*') {
            regex.append(".*");
          } else if (c == '?') {
            regex.append('.');
          } else {
            regex.append(Pattern.quote(String.valueOf(c)));
          }
        }
        patterns.add(Pattern.compile(regex.toString()));
      }
      return patterns;
    }
  }

  @Override
  public AuthorizationMode getMode() {
    return AuthorizationMode.NATIVE;
  }

  @Override
  public void init(PinotConfiguration config) {
    List<Rule> rules = new ArrayList<>();
    for (String name : list(config.getProperty("rules"))) {
      PinotConfiguration rule = config.subset("rule." + name);
      if (rule.isEmpty()) {
        throw new IllegalArgumentException("Rule '" + name + "' is listed in rules but has no settings");
      }
      rules.add(new Rule(name, new LinkedHashSet<>(list(rule.getProperty("users"))),
          new LinkedHashSet<>(list(rule.getProperty("groups"))), permissions(name, rule.getProperty("permissions")),
          list(rule.getProperty("tables")), list(rule.getProperty("excludeTables")), rule.subset("rowFilter"), false));
    }
    PinotConfiguration legacy = config.subset(LEGACY_PRINCIPALS);
    for (String name : list(config.getProperty(LEGACY_PRINCIPALS))) {
      PinotConfiguration principal = legacy.subset(name);
      List<String> tables = list(principal.getProperty("tables"));
      String permissions = principal.getProperty("permissions");
      rules.add(new Rule("basic:" + name, Set.of(name), Set.of(),
          permissions == null || permissions.trim().isEmpty() ? EnumSet.of(Permission.ALL)
              : permissions("basic:" + name, permissions),
          tables.isEmpty() ? List.of(ALL_TABLES) : tables, list(principal.getProperty("excludeTables")), principal,
          true));
    }
    _rules = List.copyOf(rules);
    LOGGER.info("Native authorization: {} rule(s): {}", _rules.size(),
        _rules.stream().map(r -> r._name).collect(Collectors.joining(", ")));
  }

  @Override
  public AuthorizationDecision authorize(PinotPrincipal principal, AccessRequest request) {
    for (Rule rule : _rules) {
      if (rule.appliesTo(principal) && rule.grants(request.getPermission()) && covers(rule, request)) {
        return AuthorizationDecision.allow("rule " + rule._name);
      }
    }
    return AuthorizationDecision.deny("no rule grants " + request.getPermission() + " on "
        + request.describeResource());
  }

  @Override
  public List<String> getRowFilters(PinotPrincipal principal, String database, String table) {
    List<List<String>> granting = new ArrayList<>();
    for (Rule rule : _rules) {
      if (rule.appliesTo(principal) && rule.grants(Permission.READ) && rule.coversTable(database, table)) {
        List<String> filters = rule.rowFilters(database, table);
        if (filters.isEmpty()) {
          // One rule grants every row
          return Collections.emptyList();
        }
        granting.add(filters);
      }
    }
    if (granting.isEmpty()) {
      return Collections.emptyList();
    }
    if (granting.size() == 1) {
      return granting.get(0);
    }
    // Several rules: the rows of any of them
    return List.of(granting.stream()
        .map(filters -> "(" + filters.stream().map(f -> "(" + f + ")").collect(Collectors.joining(" AND ")) + ")")
        .collect(Collectors.joining(" OR ")));
  }

  private static boolean covers(Rule rule, AccessRequest request) {
    switch (request.getResourceType()) {
      case CLUSTER:
        return rule.coversCluster();
      case DATABASE:
        return rule.coversDatabase(request.getDatabase());
      default:
        return rule.coversTable(request.getDatabase(), request.getTable());
    }
  }

  private static Set<Permission> permissions(String rule, @Nullable String value) {
    Set<Permission> permissions = EnumSet.noneOf(Permission.class);
    for (String name : list(value)) {
      try {
        permissions.add(Permission.fromName(name));
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("Rule '" + rule + "': " + e.getMessage(), e);
      }
    }
    return permissions;
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
