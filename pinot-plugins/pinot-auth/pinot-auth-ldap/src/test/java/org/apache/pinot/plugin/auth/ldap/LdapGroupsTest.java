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

import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.apache.pinot.plugin.auth.ldap.EmbeddedLdap.BASE;
import static org.apache.pinot.plugin.auth.ldap.EmbeddedLdap.authenticator;
import static org.apache.pinot.plugin.auth.ldap.EmbeddedLdap.basic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// User name and group modes of [LdapAuthenticator] against an OpenLDAP-style tree (`uid`, `groupOfNames`) and an
/// Active Directory-style one (`sAMAccountName`, `memberOf`, nested groups through the in-chain matching rule).
public class LdapGroupsTest {
  private static final String PEOPLE = "ou=people," + BASE;
  private static final String GROUPS = "ou=groups," + BASE;
  private static final String FRANK_DN = "cn=Frank Smith," + PEOPLE;

  private EmbeddedLdap _ldap;

  @BeforeClass
  public void startServer()
      throws Exception {
    _ldap = new EmbeddedLdap(
        // OpenLDAP style
        "dn: uid=alice," + PEOPLE, "objectClass: inetOrgPerson", "uid: alice", "cn: Alice", "sn: A",
        "userPassword: alice-pw", "",
        "dn: uid=bob," + PEOPLE, "objectClass: inetOrgPerson", "uid: bob", "cn: Bob", "sn: B",
        "userPassword: bob-pw", "",
        "dn: uid=Dave," + PEOPLE, "objectClass: inetOrgPerson", "uid: Dave", "cn: Dave", "sn: D",
        "userPassword: dave-pw", "",
        // Active Directory style: the entry is named by its display name, the sign-in name is sAMAccountName and
        // the direct groups are listed in memberOf
        "dn: " + FRANK_DN, "objectClass: user", "cn: Frank Smith", "sAMAccountName: FSmith",
        "memberOf: CN=Finance," + GROUPS, "userPassword: frank-pw", "",
        "dn: cn=analysts," + GROUPS, "objectClass: groupOfNames", "cn: analysts", "member: uid=alice," + PEOPLE, "",
        "dn: cn=Finance," + GROUPS, "objectClass: groupOfNames", "cn: Finance", "member: " + FRANK_DN, "",
        // Nested: the analysts and Finance groups are members of all-staff
        "dn: cn=all-staff," + GROUPS, "objectClass: groupOfNames", "cn: all-staff", "member: cn=analysts," + GROUPS,
        "member: cn=Finance," + GROUPS);
  }

  @AfterClass
  public void stopServer() {
    _ldap.close();
  }

  private Map<String, Object> config(String... settings) {
    Map<String, Object> config = _ldap.ldaps();
    for (int i = 0; i < settings.length; i += 2) {
      config.put(settings[i], settings[i + 1]);
    }
    return config;
  }

  @Test
  public void testGroupSearchAndNestedGroups() {
    PinotPrincipal alice = authenticator(config("group.mode", "search", "group.search.base", GROUPS))
        .authenticate(basic("alice", "alice-pw"));
    assertEquals(alice.getGroups(), Set.of("analysts"));
    // Directories without a chain rule: nested groups by searching again with each group's DN
    alice = authenticator(config("group.mode", "search", "group.search.base", GROUPS, "group.nested", "true"))
        .authenticate(basic("alice", "alice-pw"));
    assertEquals(alice.getGroups(), Set.of("analysts", "all-staff"));
    // Depth limit
    alice = authenticator(config("group.mode", "search", "group.search.base", GROUPS, "group.nested", "true",
        "group.nested.depth", "0")).authenticate(basic("alice", "alice-pw"));
    assertEquals(alice.getGroups(), Set.of("analysts"));
    PinotPrincipal bob = authenticator(config("group.mode", "search", "group.search.base", GROUPS))
        .authenticate(basic("bob", "bob-pw"));
    assertEquals(bob.getGroups(), Set.of());
    // Default: no groups from the directory
    assertEquals(authenticator(config()).authenticate(basic("alice", "alice-pw")).getGroups(), Set.of());
  }

  @Test
  public void testActiveDirectoryMemberOfAndUserName() {
    PinotPrincipal frank = authenticator(config("user.search.filter", "(sAMAccountName={0})", "user.name.attribute",
        "sAMAccountName", "group.mode", "memberof")).authenticate(basic("fsmith", "frank-pw"));
    // Lower-cased, as Ranger UserSync names users and groups
    assertEquals(frank.getUser(), "fsmith");
    assertEquals(frank.getGroups(), Set.of("finance"));
    assertEquals(frank.getClaims().get("dn"), FRANK_DN);
  }

  @Test
  public void testActiveDirectoryInChainRule() {
    _ldap._searchFilters.clear();
    PinotPrincipal frank = authenticator(config("user.search.filter", "(sAMAccountName={0})", "user.name.attribute",
        "sAMAccountName", "group.mode", "search", "group.search.base", GROUPS, "group.search.filter",
        "(member:" + EmbeddedLdap.IN_CHAIN + ":={1})")).authenticate(basic("fsmith", "frank-pw"));
    assertEquals(frank.getGroups(), Set.of("finance", "all-staff"));
    // The server got the chain rule with the user's DN
    assertTrue(_ldap._searchFilters.stream().anyMatch(f -> f.contains(EmbeddedLdap.IN_CHAIN) && f.contains("Frank")),
        _ldap._searchFilters.toString());
  }

  @Test
  public void testSearchReferencesFromTheDomainRoot() {
    // Active Directory answers a search from the domain root with the entries and references to its other
    // partitions; the references are not followed and must not fail the sign-in or the group lookup
    _ldap._sendReferences = true;
    try {
      PinotPrincipal frank = authenticator(config("user.search.base", BASE, "user.search.filter",
          "(sAMAccountName={0})", "user.name.attribute", "sAMAccountName", "group.mode", "search",
          "group.search.base", BASE, "group.search.filter", "(member:" + EmbeddedLdap.IN_CHAIN + ":={1})"))
          .authenticate(basic("fsmith", "frank-pw"));
      assertEquals(frank.getUser(), "fsmith");
      assertEquals(frank.getGroups(), Set.of("finance", "all-staff"));
    } finally {
      _ldap._sendReferences = false;
    }
    expectThrows(IllegalArgumentException.class, () -> authenticator(config("referral", "sometimes")));
  }

  @Test
  public void testCaseOfNames() {
    PinotPrincipal dave = authenticator(config()).authenticate(basic("dave", "dave-pw"));
    assertEquals(dave.getUser(), "dave");
    dave = authenticator(config("user.name.lowercase", "false")).authenticate(basic("dave", "dave-pw"));
    assertEquals(dave.getUser(), "Dave");
    PinotPrincipal frank = authenticator(config("user.search.filter", "(sAMAccountName={0})", "user.name.attribute",
        "sAMAccountName", "group.mode", "memberof", "group.name.lowercase", "false"))
        .authenticate(basic("fsmith", "frank-pw"));
    assertEquals(frank.getGroups(), Set.of("Finance"));
  }

  @Test
  public void testRequiredGroup() {
    LdapAuthenticator authenticator = authenticator(config("group.mode", "search", "group.search.base", GROUPS,
        "group.nested", "true", "required.group", "All-Staff"));
    assertEquals(authenticator.authenticate(basic("alice", "alice-pw")).getUser(), "alice");
    AuthenticationException e =
        expectThrows(AuthenticationException.class, () -> authenticator.authenticate(basic("bob", "bob-pw")));
    assertEquals(e.getMessage(), "Invalid user name or password");
  }

  @Test
  public void testFailedGroupLookupRefusesTheSignIn() {
    // Without its groups a principal could escape a group's deny rule: the sign-in is refused, not let through
    LdapAuthenticator authenticator =
        authenticator(config("group.mode", "search", "group.search.base", "ou=missing," + BASE));
    AuthenticationException e =
        expectThrows(AuthenticationException.class, () -> authenticator.authenticate(basic("alice", "alice-pw")));
    assertEquals(e.getMessage(), "Directory unavailable");
    expectThrows(IllegalArgumentException.class, () -> authenticator(config("group.mode", "search")));
    expectThrows(IllegalArgumentException.class, () -> authenticator(config("group.mode", "everything")));
  }
}
