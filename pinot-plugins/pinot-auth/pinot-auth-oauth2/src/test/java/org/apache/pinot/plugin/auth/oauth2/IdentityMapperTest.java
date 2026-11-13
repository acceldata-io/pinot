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

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [IdentityMapper]: user-name rules, group clean-up and filters, required scopes, scopes as groups, service accounts.
public class IdentityMapperTest {

  private static IdentityMapper mapper(String... keyValues) {
    Map<String, Object> settings = new HashMap<>();
    for (int i = 0; i < keyValues.length; i += 2) {
      settings.put(keyValues[i], keyValues[i + 1]);
    }
    return new IdentityMapper("idp", new PinotConfiguration(settings));
  }

  private static TokenIdentity identity(String user, Set<String> groups, Set<String> scopes,
      Map<String, Object> attributes) {
    return new TokenIdentity(user, groups, scopes, Instant.now().plusSeconds(300), "https://idp", attributes);
  }

  @Test
  public void testUserRules() {
    IdentityMapper mapper = mapper("user.rules",
        "^([^@]+)@example\\.com$/$1/L; ^svc-(.*)@clients\\.example\\.com$/service-$1/; ^(.*)\\\\(.*)$/$2/L");
    assertEquals(mapper.map(identity("Alice.Smith@example.com", Set.of(), Set.of(), Map.of())).getUser(),
        "alice.smith");
    assertEquals(mapper.map(identity("svc-ingest@clients.example.com", Set.of(), Set.of(), Map.of())).getUser(),
        "service-ingest");
    assertEquals(mapper.map(identity("CORP\\Bob", Set.of(), Set.of(), Map.of())).getUser(), "bob");
    // Unmatched names are kept by default, and the token's own name is kept for audit
    PinotPrincipal kept = mapper.map(identity("carol@other.org", Set.of(), Set.of(), Map.of()));
    assertEquals(kept.getUser(), "carol@other.org");
    assertEquals(mapper.map(identity("Alice@example.com", Set.of(), Set.of(), Map.of())).getClaims()
        .get("token_user"), "Alice@example.com");
    // ... or refused
    IdentityMapper strict = mapper("user.rules", "^([^@]+)@example\\.com$/$1/L", "user.rules.unmatched", "reject");
    expectThrows(AuthenticationException.class,
        () -> strict.map(identity("carol@other.org", Set.of(), Set.of(), Map.of())));
  }

  @Test
  public void testGroupsAndScopes() {
    IdentityMapper mapper = mapper("groups.prefix.strip", "/,ROLE_", "groups.lower", "true",
        "groups.exclude", "default-roles-.*|offline_access", "scopes.as.groups", "true");
    PinotPrincipal principal = mapper.map(identity("alice",
        Set.of("/Pinot-Analysts", "ROLE_OPS", "default-roles-master", "offline_access"),
        Set.of("pinot.read"), Map.of()));
    assertEquals(principal.getGroups(), Set.of("pinot-analysts", "ops", "scope:pinot.read"));

    IdentityMapper onlyPinot = mapper("groups.include", "pinot-.*");
    assertEquals(onlyPinot.map(identity("a", Set.of("pinot-ops", "hr"), Set.of(), Map.of())).getGroups(),
        Set.of("pinot-ops"));

    IdentityMapper scoped = mapper("required.scopes", "pinot.read,pinot.query");
    assertEquals(scoped.map(identity("a", Set.of(), Set.of("pinot.read", "pinot.query", "email"), Map.of()))
        .getUser(), "a");
    AuthenticationException e = expectThrows(AuthenticationException.class,
        () -> scoped.map(identity("a", Set.of(), Set.of("pinot.read"), Map.of())));
    assertTrue(e.getMessage().contains("pinot.query"));
  }

  @Test
  public void testServiceAccounts() {
    IdentityMapper byUser = mapper("service.users", "svc-pinot");
    assertTrue(byUser.map(identity("svc-pinot", Set.of(), Set.of(), Map.of())).isServiceAccount());
    assertFalse(byUser.map(identity("alice", Set.of(), Set.of(), Map.of())).isServiceAccount());

    IdentityMapper byClaim = mapper("service.claim", "azp", "service.claim.values", "pinot-controller,pinot-server");
    assertTrue(byClaim.map(identity("service-account-pinot-server", Set.of(), Set.of(),
        Map.of("azp", "pinot-server"))).isServiceAccount());
    assertFalse(byClaim.map(identity("alice", Set.of(), Set.of(), Map.of("azp", "pinot-ui"))).isServiceAccount());
    assertTrue(byClaim.map(identity("x", Set.of(), Set.of(), Map.of("azp", List.of("other", "pinot-controller"))))
        .isServiceAccount());
  }

  @Test
  public void testConfigurationErrors() {
    expectThrows(IllegalArgumentException.class, () -> mapper("user.rules", "no-slashes"));
    expectThrows(IllegalArgumentException.class, () -> mapper("user.rules", "^(.*$/$1/"));
    expectThrows(IllegalArgumentException.class, () -> mapper("user.rules", "^(.*)$/$1/X"));
    expectThrows(IllegalArgumentException.class, () -> mapper("user.rules.unmatched", "drop"));
    expectThrows(IllegalArgumentException.class, () -> mapper("service.claim", "azp"));
    expectThrows(IllegalArgumentException.class, () -> mapper("groups.include", "[unclosed"));
  }
}
