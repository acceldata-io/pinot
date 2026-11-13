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
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.audit.AuditUserIdentity;
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

  private AccessEnforcer enforcer(boolean enforce) {
    return new AccessEnforcer(new TestAuth.Authenticator(), new TestAuth.Authorizer(), enforce, Set.of(),
        new AuthAuditLog(_events::add));
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
}
