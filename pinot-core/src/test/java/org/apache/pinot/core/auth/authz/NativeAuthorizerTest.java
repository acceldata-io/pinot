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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [NativeAuthorizer]: subjects (users, groups), permissions, table globs and exclusions, cluster and database scope,
/// row filters, BasicAuth principals read as rules, and start-up validation.
public class NativeAuthorizerTest {

  private static NativeAuthorizer authorizer(String... keyValues) {
    Map<String, Object> settings = new HashMap<>();
    for (int i = 0; i < keyValues.length; i += 2) {
      settings.put(keyValues[i], keyValues[i + 1]);
    }
    NativeAuthorizer authorizer = new NativeAuthorizer();
    authorizer.init(new PinotConfiguration(settings));
    return authorizer;
  }

  private static NativeAuthorizer standardRules() {
    return authorizer(
        "rules", "analysts,ingest,admins,finance_ops",
        "rule.analysts.groups", "pinot-analysts",
        "rule.analysts.permissions", "READ",
        "rule.analysts.tables", "orders,orders_*,fin.*",
        "rule.analysts.rowFilter.orders", "region = 'south'",
        "rule.ingest.users", "svc-ci",
        "rule.ingest.permissions", "READ,CREATE,UPDATE",
        "rule.ingest.tables", "fin.*",
        "rule.ingest.excludeTables", "fin.audit",
        "rule.admins.groups", "pinot-admins",
        "rule.admins.permissions", "ALL",
        "rule.admins.tables", "*",
        "rule.finance_ops.users", "carol",
        "rule.finance_ops.permissions", "ALL",
        "rule.finance_ops.tables", "fin.*");
  }

  private static PinotPrincipal principal(String user, String... groups) {
    return new PinotPrincipal(user, Set.of(groups), AuthMethod.OAUTH2, false, Map.of());
  }

  private static boolean allowed(NativeAuthorizer authorizer, PinotPrincipal principal, TargetType targetType,
      String targetId, String action) {
    ActionPermissions.Requirement requirement = ActionPermissions.get(targetType, action);
    AccessRequest request = AccessEnforcer.request(targetType, targetId, action, requirement.getPermission(),
        requirement.getAccessType());
    return authorizer.authorize(principal, request).isAllowed();
  }

  @Test
  public void testTablesGroupsAndPermissions() {
    NativeAuthorizer authorizer = standardRules();
    PinotPrincipal analyst = principal("alice", "pinot-analysts");
    assertTrue(allowed(authorizer, analyst, TargetType.TABLE, "orders_OFFLINE", Actions.Table.QUERY));
    assertTrue(allowed(authorizer, analyst, TargetType.TABLE, "orders_eu_REALTIME", Actions.Table.GET_SCHEMA));
    assertTrue(allowed(authorizer, analyst, TargetType.TABLE, "fin.payments", Actions.Table.QUERY));
    assertFalse(allowed(authorizer, analyst, TargetType.TABLE, "cities", Actions.Table.QUERY));
    assertFalse(allowed(authorizer, analyst, TargetType.TABLE, "orders", Actions.Table.DELETE_TABLE));
    // The default database name may be written out
    assertTrue(allowed(authorizer, analyst, TargetType.TABLE, "default.orders", Actions.Table.QUERY));
    // Not in the group: nothing
    assertFalse(allowed(authorizer, principal("bob"), TargetType.TABLE, "orders", Actions.Table.QUERY));

    PinotPrincipal ingest = principal("svc-ci");
    assertTrue(allowed(authorizer, ingest, TargetType.TABLE, "fin.payments", Actions.Table.UPLOAD_SEGMENT));
    assertFalse(allowed(authorizer, ingest, TargetType.TABLE, "fin.audit", Actions.Table.QUERY));
    assertFalse(allowed(authorizer, ingest, TargetType.TABLE, "fin.payments", Actions.Table.DELETE_TABLE));
  }

  @Test
  public void testClusterAndDatabaseScope() {
    NativeAuthorizer authorizer = standardRules();
    // apache/pinot#14595: a principal limited to some tables gets nothing cluster-wide, not even reads
    assertFalse(allowed(authorizer, principal("alice", "pinot-analysts"), TargetType.CLUSTER, null,
        Actions.Cluster.GET_TABLE));
    assertFalse(allowed(authorizer, principal("carol"), TargetType.CLUSTER, null, Actions.Cluster.GET_INSTANCE));
    // A rule on every table covers the cluster, including ZooKeeper and users with ADMIN
    PinotPrincipal admin = principal("dave", "pinot-admins");
    assertTrue(allowed(authorizer, admin, TargetType.CLUSTER, null, Actions.Cluster.UPDATE_ZNODE));
    assertTrue(allowed(authorizer, admin, TargetType.CLUSTER, null, Actions.Cluster.CREATE_USER));
    // ADMIN needs an ADMIN or ALL grant even with every table
    NativeAuthorizer readAll = authorizer("rules", "r", "rule.r.users", "erin", "rule.r.permissions",
        "READ,CREATE,UPDATE,DELETE", "rule.r.tables", "*");
    assertTrue(allowed(readAll, principal("erin"), TargetType.CLUSTER, null, Actions.Cluster.GET_TABLE));
    assertFalse(allowed(readAll, principal("erin"), TargetType.CLUSTER, null, Actions.Cluster.UPDATE_ZNODE));
    // A database is covered by <database>.* (without exclusions) or *
    assertTrue(allowed(authorizer, principal("carol"), TargetType.DATABASE, "fin", Actions.Database.DELETE_DATABASE));
    assertFalse(allowed(authorizer, principal("carol"), TargetType.DATABASE, "sales",
        Actions.Database.DELETE_DATABASE));
    assertFalse(allowed(authorizer, principal("svc-ci"), TargetType.DATABASE, "fin",
        Actions.Database.GET_DATABASE_QUOTA));
  }

  @Test
  public void testRowFilters() {
    NativeAuthorizer authorizer = authorizer(
        "rules", "south,north,all_orders",
        "rule.south.groups", "south",
        "rule.south.permissions", "READ",
        "rule.south.tables", "orders",
        "rule.south.rowFilter.orders", "region = 'south'",
        "rule.north.groups", "north",
        "rule.north.permissions", "READ",
        "rule.north.tables", "orders",
        "rule.north.rowFilter.orders", "region = 'north'",
        "rule.all_orders.groups", "auditors",
        "rule.all_orders.permissions", "READ",
        "rule.all_orders.tables", "orders");
    assertEquals(authorizer.getRowFilters(principal("a", "south"), "default", "orders"), List.of("region = 'south'"));
    assertEquals(authorizer.getRowFilters(principal("b", "south", "north"), "default", "orders"),
        List.of("((region = 'south')) OR ((region = 'north'))"));
    // A rule without a filter grants every row
    assertEquals(authorizer.getRowFilters(principal("c", "south", "auditors"), "default", "orders"), List.of());
  }

  @Test
  public void testBasicAuthPrincipalsAsRules() {
    NativeAuthorizer authorizer = authorizer(
        "legacy.principals", "admin,user_456",
        "legacy.principals.admin.password", "ignored",
        "legacy.principals.user_456.tables", "stuff,lessImportantStuff",
        "legacy.principals.user_456.permissions", "read,update",
        "legacy.principals.user_456.stuff.rls", "owner = 'u456', active = true");
    // No permissions and no tables: everything, as with BasicAuth
    assertTrue(allowed(authorizer, principal("admin"), TargetType.CLUSTER, null, Actions.Cluster.UPDATE_ZNODE));
    PinotPrincipal user = principal("user_456");
    assertTrue(allowed(authorizer, user, TargetType.TABLE, "stuff_OFFLINE", Actions.Table.QUERY));
    assertTrue(allowed(authorizer, user, TargetType.TABLE, "stuff", Actions.Table.UPDATE_TABLE_CONFIG));
    assertFalse(allowed(authorizer, user, TargetType.TABLE, "stuff", Actions.Table.DELETE_TABLE));
    assertFalse(allowed(authorizer, user, TargetType.TABLE, "other", Actions.Table.QUERY));
    // The #14595 reproduction: a table-scoped BasicAuth user on a cluster endpoint
    assertFalse(allowed(authorizer, user, TargetType.CLUSTER, null, Actions.Cluster.GET_TABLE));
    // BasicAuth RLS filters are all required, as the broker applies them today
    assertEquals(authorizer.getRowFilters(user, "default", "stuff"), List.of("owner = 'u456'", "active = true"));
  }

  @Test
  public void testValidation() {
    expectThrows(IllegalArgumentException.class, () -> authorizer("rules", "r", "rule.r.users", "a",
        "rule.r.permissions", "WRITE", "rule.r.tables", "*"));
    expectThrows(IllegalArgumentException.class, () -> authorizer("rules", "r", "rule.r.permissions", "READ",
        "rule.r.tables", "*"));
    expectThrows(IllegalArgumentException.class, () -> authorizer("rules", "r", "rule.r.users", "a",
        "rule.r.permissions", "READ"));
    expectThrows(IllegalArgumentException.class, () -> authorizer("rules", "r", "rule.r.users", "a",
        "rule.r.permissions", "READ", "rule.r.tables", "orders;drop"));
    expectThrows(IllegalArgumentException.class, () -> authorizer("rules", "missing"));
    // No rules at all: everything is denied
    assertFalse(authorizer().authorize(principal("a"), AccessEnforcer.request(TargetType.TABLE, "orders", null,
        Permission.READ, "query")).isAllowed());
  }
}
