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

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.ResourceType;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [AccessEnforcer]: resource mapping, action requirements, service accounts, fail-closed authorizer errors and the
/// audit-only mode.
public class AccessEnforcerTest {

  @BeforeMethod
  public void reset() {
    TestAuth.Authorizer.ALLOWED.clear();
    TestAuth.Authorizer.SEEN.clear();
  }

  private static AccessEnforcer enforcer(String... extra) {
    Map<String, Object> settings = TestAuth.settings();
    for (int i = 0; i < extra.length; i += 2) {
      settings.put(extra[i], extra[i + 1]);
    }
    return AccessEnforcer.create(new PinotConfiguration(settings));
  }

  private static PinotPrincipal user(String name) {
    return new PinotPrincipal(name, Set.of(), AuthMethod.OAUTH2, false, Map.of());
  }

  @Test
  public void testResourceMapping() {
    AccessRequest table = AccessEnforcer.request(TargetType.TABLE, "orders_REALTIME", "GetSchema", Permission.READ,
        "read_metadata");
    assertEquals(table.getResourceType(), ResourceType.TABLE);
    assertEquals(table.getDatabase(), "default");
    assertEquals(table.getTable(), "orders");
    AccessRequest qualified = AccessEnforcer.request(TargetType.TABLE, "fin.payments_OFFLINE", null, Permission.READ,
        "query");
    assertEquals(qualified.getDatabase(), "fin");
    assertEquals(qualified.getTable(), "payments");
    AccessRequest database = AccessEnforcer.request(TargetType.DATABASE, "fin", "DeleteDatabase", Permission.DELETE,
        "manage_database");
    assertEquals(database.getResourceType(), ResourceType.DATABASE);
    assertEquals(database.getDatabase(), "fin");
    assertNull(database.getTable());
    // A table or database target without a name is cluster-wide
    assertEquals(AccessEnforcer.request(TargetType.TABLE, null, null, Permission.READ, "read_metadata")
        .getResourceType(), ResourceType.CLUSTER);
    assertEquals(AccessEnforcer.request(TargetType.CLUSTER, "ignored", null, Permission.ADMIN, "manage_users")
        .getResourceType(), ResourceType.CLUSTER);
  }

  @Test
  public void testActionsGoThroughTheAuthorizer() {
    AccessEnforcer enforcer = enforcer();
    TestAuth.Authorizer.ALLOWED.add("alice GetSchema on default.orders");
    assertTrue(enforcer.isAllowed(user("alice"), TargetType.TABLE, "orders_OFFLINE", Actions.Table.GET_SCHEMA));
    assertFalse(enforcer.isAllowed(user("alice"), TargetType.TABLE, "orders_OFFLINE", Actions.Table.DELETE_TABLE));
    assertEquals(TestAuth.Authorizer.SEEN, List.of("alice GetSchema on default.orders",
        "alice DeleteTable on default.orders"));
    // Unknown actions are denied without asking the authorizer; the UI sign-in check needs no rule
    assertFalse(enforcer.isAllowed(user("alice"), TargetType.TABLE, "orders", "MadeUpAction"));
    assertTrue(enforcer.isAllowed(user("alice"), TargetType.CLUSTER, null, Actions.Cluster.GET_AUTH));
    assertEquals(TestAuth.Authorizer.SEEN.size(), 2);
  }

  @Test
  public void testServiceAccountsAndFailClosed() {
    AccessEnforcer enforcer = enforcer("pinot.authz.service.accounts", "svc-pinot");
    assertTrue(enforcer.isAllowed(user("svc-pinot"), TargetType.CLUSTER, null, Actions.Cluster.UPDATE_ZNODE));
    PinotPrincipal markedService = new PinotPrincipal("client-x", Set.of(), AuthMethod.OAUTH2, true, Map.of());
    assertTrue(enforcer.isAllowed(markedService, TargetType.CLUSTER, null, Actions.Cluster.DELETE_USER));
    assertTrue(TestAuth.Authorizer.SEEN.isEmpty());
    // An authorizer failure denies
    assertFalse(enforcer.isAllowed(user("boom"), TargetType.TABLE, "orders", Actions.Table.QUERY));
  }

  @Test
  public void testAuditOnlyMode() {
    AccessEnforcer enforcer = enforcer("pinot.authz.enforce", "false");
    assertTrue(enforcer.isAllowed(user("alice"), TargetType.TABLE, "orders", Actions.Table.DELETE_TABLE));
    // Still evaluated, so the denial can be logged
    assertEquals(TestAuth.Authorizer.SEEN, List.of("alice DeleteTable on default.orders"));
    // Unknown actions stay denied: there is nothing to evaluate them against
    assertFalse(enforcer.isAllowed(user("alice"), TargetType.TABLE, "orders", "MadeUpAction"));
  }

  @Test
  public void testAuthentication() {
    AccessEnforcer enforcer = enforcer();
    assertEquals(enforcer.getMethod(), AuthMethod.OAUTH2);
    PinotPrincipal principal = enforcer.authenticate("Bearer alice:analysts,ops");
    assertEquals(principal.getUser(), "alice");
    assertEquals(principal.getGroups(), Set.of("analysts", "ops"));
    AuthenticationException missing = expectThrows(AuthenticationException.class, () -> enforcer.authenticate(null));
    assertTrue(missing.getChallenge().startsWith("Bearer realm=\"pinot\""));
    // A credential of another type than the cluster's method is refused before the method sees it
    expectThrows(AuthenticationException.class, () -> enforcer.authenticate("Basic YWRtaW46dmVyeXNlY3JldA=="));
    expectThrows(AuthenticationException.class, () -> enforcer.authenticate("Bearer bad"));
    // Without a method the enforcer cannot be created
    expectThrows(IllegalStateException.class, () -> AccessEnforcer.create(new PinotConfiguration()));
  }
}
