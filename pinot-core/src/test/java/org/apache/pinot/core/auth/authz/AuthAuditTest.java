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

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.audit.AuditUserIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.JsonUtils;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// Security audit events of [AccessEnforcer] and the request-audit identity of [PinotAuthAuditTokenResolver].
public class AuthAuditTest {
  private final List<String> _events = new CopyOnWriteArrayList<>();

  @BeforeMethod
  public void reset() {
    _events.clear();
    TestAuth.Authorizer.ALLOWED.clear();
    TestAuth.Authorizer.SEEN.clear();
  }

  private final List<String> _allowedEvents = new CopyOnWriteArrayList<>();

  private AccessEnforcer enforcer(boolean enforce) {
    return new AccessEnforcer(new TestAuth.Authenticator(), new TestAuth.Authorizer(), enforce, Set.of(), false,
        new AuthAuditLog(_events::add));
  }

  @Test
  public void testAllowedDecisionsAreAuditedOnRequest()
      throws Exception {
    _allowedEvents.clear();
    TestAuth.Authorizer.ALLOWED.add("alice Query on default.orders");
    AccessEnforcer all = new AccessEnforcer(new TestAuth.Authenticator(), new TestAuth.Authorizer(), true,
        Set.of("svc-pinot"), true, new AuthAuditLog(_events::add, _allowedEvents::add));
    PinotPrincipal alice = all.authenticate("Bearer alice:analysts");
    PinotPrincipal service = all.authenticate("Bearer svc-pinot");
    // The sign-in event already marks it as a service account
    assertTrue(JsonUtils.stringToJsonNode(_events.get(_events.size() - 1)).get("serviceAccount").asBoolean());
    _events.clear();
    assertTrue(all.isAllowed(alice, TargetType.TABLE, "orders", Actions.Table.QUERY));
    assertTrue(all.isAllowed(service, TargetType.CLUSTER, null, Actions.Cluster.UPDATE_ZNODE));
    assertFalse(all.isAllowed(alice, TargetType.TABLE, "orders", Actions.Table.DELETE_TABLE));
    // Allowed decisions on their own (INFO) sink, denials on the WARN one
    assertEquals(_allowedEvents.size(), 2);
    assertEquals(_events.size(), 1);
    JsonNode allowed = JsonUtils.stringToJsonNode(_allowedEvents.get(0));
    assertEquals(allowed.get("outcome").asText(), "allowed");
    assertEquals(allowed.get("user").asText(), "alice");
    assertEquals(allowed.get("groups").get(0).asText(), "analysts");
    assertEquals(allowed.get("mode").asText(), "native");
    assertEquals(allowed.get("method").asText(), "oauth2");
    assertEquals(allowed.get("resource").asText(), "default.orders");
    assertEquals(allowed.get("action").asText(), "Query");
    assertEquals(allowed.get("reason").asText(), "listed", "the rule or policy that allowed it");
    JsonNode serviceAllowed = JsonUtils.stringToJsonNode(_allowedEvents.get(1));
    assertEquals(serviceAllowed.get("reason").asText(), "service account");
    assertTrue(serviceAllowed.get("serviceAccount").asBoolean(), "service account by pinot.authz.service.accounts");
    assertFalse(allowed.get("serviceAccount").asBoolean());
    all.close();

    // Default: denials only
    _allowedEvents.clear();
    AccessEnforcer denied = new AccessEnforcer(new TestAuth.Authenticator(), new TestAuth.Authorizer(), true, Set.of(),
        false, new AuthAuditLog(_events::add, _allowedEvents::add));
    assertTrue(denied.isAllowed(alice, TargetType.TABLE, "orders", Actions.Table.QUERY));
    assertTrue(_allowedEvents.isEmpty());
    denied.close();
  }

  @Test
  public void testAuditSettingIsChecked() {
    Map<String, Object> settings = TestAuth.settings();
    settings.put("pinot.authz.audit", "everything");
    expectThrows(IllegalArgumentException.class, () -> AccessEnforcer.create(new PinotConfiguration(settings)));
    settings.put("pinot.authz.audit", "all");
    AccessEnforcer.create(new PinotConfiguration(settings)).close();
  }

  @Test
  public void testAuthenticationEvents()
      throws Exception {
    AccessEnforcer enforcer = enforcer(true);
    enforcer.authenticate("Bearer alice:analysts");
    enforcer.authenticate("Bearer alice:analysts");
    // One sign-in event per credential, not one per request
    assertEquals(_events.size(), 1);
    JsonNode success = JsonUtils.stringToJsonNode(_events.get(0));
    assertEquals(success.get("event").asText(), "authentication");
    assertEquals(success.get("outcome").asText(), "success");
    assertEquals(success.get("method").asText(), "oauth2");
    assertEquals(success.get("user").asText(), "alice");
    assertEquals(success.get("groups").get(0).asText(), "analysts");

    expectThrows(AuthenticationException.class, () -> enforcer.authenticate("Bearer bad"));
    expectThrows(AuthenticationException.class, () -> enforcer.authenticate(null));
    JsonNode failure = JsonUtils.stringToJsonNode(_events.get(1));
    assertEquals(failure.get("outcome").asText(), "failure");
    assertEquals(failure.get("reason").asText(), "Invalid token");
    assertEquals(_events.size(), 3);
    // Never a credential
    for (String event : _events) {
      assertFalse(event.contains("alice:analysts"), event);
      assertFalse(event.contains("Bearer bad"), event);
    }
    enforcer.close();
  }

  @Test
  public void testAuthorizationEvents()
      throws Exception {
    AccessEnforcer enforcer = enforcer(true);
    PinotPrincipal alice = enforcer.authenticate("Bearer alice");
    _events.clear();
    assertFalse(enforcer.isAllowed(alice, TargetType.TABLE, "orders_OFFLINE", Actions.Table.DELETE_TABLE));
    JsonNode denied = JsonUtils.stringToJsonNode(_events.get(0));
    assertEquals(denied.get("event").asText(), "authorization");
    assertEquals(denied.get("outcome").asText(), "denied");
    assertEquals(denied.get("mode").asText(), "native");
    assertEquals(denied.get("resource").asText(), "default.orders");
    assertEquals(denied.get("action").asText(), "DeleteTable");
    assertEquals(denied.get("permission").asText(), "DELETE");
    assertEquals(denied.get("reason").asText(), "not listed");
    enforcer.close();

    AccessEnforcer auditOnly = enforcer(false);
    assertTrue(auditOnly.isAllowed(alice, TargetType.TABLE, "orders", Actions.Table.DELETE_TABLE));
    assertEquals(JsonUtils.stringToJsonNode(_events.get(1)).get("outcome").asText(), "wouldDeny");
    auditOnly.close();
  }

  @Test
  public void testRequestAuditIdentity() {
    AccessEnforcer enforcer = enforcer(true);
    PinotAuthAuditTokenResolver resolver = new PinotAuthAuditTokenResolver();
    assertNull(resolver.resolve("Bearer carol"));
    enforcer.authenticate("Bearer carol");
    AuditUserIdentity identity = resolver.resolve("Bearer carol");
    assertEquals(identity.getPrincipal(), "carol");
    assertEquals(identity.getAuthMethod(), "oauth2");
    enforcer.close();
    assertNull(resolver.resolve("Bearer carol"));
  }

  @Test
  public void testRowFiltersAreAudited()
      throws Exception {
    _allowedEvents.clear();
    TestAuth.Authorizer.ROW_FILTERS.clear();
    TestAuth.Authorizer.ROW_FILTERS.put("alice default.orders", List.of("region = 'south'"));
    TestAuth.Authorizer.ROW_FILTERS.put("mallory default.customers", List.of("region = = 'x'"));
    try {
      AccessEnforcer all = new AccessEnforcer(new TestAuth.Authenticator(), new TestAuth.Authorizer(), true, Set.of(),
          true, new AuthAuditLog(_events::add, _allowedEvents::add));
      PinotPrincipal alice = all.authenticate("Bearer alice:analysts");
      PinotPrincipal mallory = all.authenticate("Bearer mallory");
      _events.clear();
      // A filter that applies: allowed, with the filter the rows are restricted to
      assertEquals(all.getRowFilters(alice, "orders_OFFLINE"), List.of("region = 'south'"));
      assertEquals(_allowedEvents.size(), 1);
      JsonNode applied = JsonUtils.stringToJsonNode(_allowedEvents.get(0));
      assertEquals(applied.get("outcome").asText(), "allowed");
      assertEquals(applied.get("user").asText(), "alice");
      assertEquals(applied.get("resource").asText(), "default.orders");
      assertEquals(applied.get("action").asText(), AccessEnforcer.ROW_FILTER_ACTION);
      assertEquals(applied.get("reason").asText(), "rows restricted to ( region = 'south' )");
      // A filter that does not parse: the broker refuses the query, the audit says so (a denial, always recorded)
      assertEquals(all.getRowFilters(mallory, "customers"), List.of("region = = 'x'"));
      assertEquals(_events.size(), 1);
      JsonNode refused = JsonUtils.stringToJsonNode(_events.get(0));
      assertEquals(refused.get("outcome").asText(), "denied");
      assertEquals(refused.get("user").asText(), "mallory");
      assertEquals(refused.get("action").asText(), AccessEnforcer.ROW_FILTER_ACTION);
      assertTrue(refused.get("reason").asText().startsWith("row filter does not parse"));
      // No filter: no event; with only denials audited, an applied filter is not recorded
      assertEquals(all.getRowFilters(alice, "customers"), List.of());
      assertEquals(_allowedEvents.size(), 1);
      AccessEnforcer deniedOnly = enforcer(true);
      PinotPrincipal alice2 = deniedOnly.authenticate("Bearer alice:analysts");
      _events.clear();
      deniedOnly.getRowFilters(alice2, "orders");
      assertEquals(_events.size(), 0);
      deniedOnly.getRowFilters(deniedOnly.authenticate("Bearer mallory"), "customers");
      assertEquals(JsonUtils.stringToJsonNode(_events.get(_events.size() - 1)).get("outcome").asText(), "denied");
    } finally {
      TestAuth.Authorizer.ROW_FILTERS.clear();
    }
  }
}
