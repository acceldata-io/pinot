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

import java.io.File;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethodSelector;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [LdapAuthenticator] against an embedded directory with plain LDAP, LDAPS and StartTLS listeners: both bind modes
/// (including an Active Directory principal name), transport rules, trust, failover and rejected credentials.
public class LdapAuthenticatorTest {
  private static final String BASE = EmbeddedLdap.BASE;
  private static final String ALICE_PASSWORD = "alice-test-password";
  private static final SecretResolver SECRETS = EmbeddedLdap.SECRETS;

  private EmbeddedLdap _ldap;
  private int _ldapPort;
  private int _ldapsPort;
  private int _otherHostPort;
  private File _truststore;

  @BeforeClass
  public void startServer()
      throws Exception {
    _ldap = new EmbeddedLdap(
        "dn: uid=alice,ou=people," + BASE, "objectClass: inetOrgPerson", "uid: alice", "cn: Alice", "sn: A",
        "userPassword: " + ALICE_PASSWORD, "",
        "dn: uid=o\\,brien,ou=people," + BASE, "objectClass: inetOrgPerson", "uid: o,brien", "cn: OBrien", "sn: O",
        "userPassword: obrien-test-password", "",
        "dn: ou=Sales\\, East," + BASE, "objectClass: organizationalUnit", "ou: Sales, East", "",
        "dn: cn=bind\\, sales,ou=Sales\\, East," + BASE, "objectClass: person", "cn: bind, sales", "sn: s",
        "userPassword: sales-bind-test-password", "",
        "dn: uid=alice2,ou=people," + BASE, "objectClass: inetOrgPerson", "uid: alice2", "cn: Alice", "sn: A",
        "userPassword: other-test-password");
    _ldapPort = _ldap._ldapPort;
    _ldapsPort = _ldap._ldapsPort;
    _otherHostPort = _ldap._otherHostPort;
    _truststore = _ldap._truststore;
  }

  @AfterClass
  public void stopServer() {
    _ldap.close();
  }

  @BeforeMethod
  public void resetCounters() {
    _ldap._binds.set(0);
  }

  Map<String, Object> ldaps() {
    return _ldap.ldaps();
  }

  static LdapAuthenticator authenticator(Map<String, Object> config) {
    return EmbeddedLdap.authenticator(config);
  }

  static AuthCredential basic(String user, String password) {
    return EmbeddedLdap.basic(user, password);
  }

  static void assertRefused(PinotAuthenticator authenticator, AuthCredential credential, String message) {
    AuthenticationException e =
        expectThrows(AuthenticationException.class, () -> authenticator.authenticate(credential));
    assertTrue(e.getMessage().startsWith(message), e.getMessage());
    assertEquals(e.getChallenge(), "Basic realm=\"pinot\"");
  }

  @Test
  public void testSearchThenBindOverLdaps() {
    LdapAuthenticator authenticator = authenticator(ldaps());
    PinotPrincipal principal = authenticator.authenticate(basic("alice", ALICE_PASSWORD));
    assertEquals(principal.getUser(), "alice");
    assertEquals(principal.getClaims().get("dn"), "uid=alice,ou=people," + BASE);
    assertFalse(principal.isServiceAccount());
    assertRefused(authenticator, basic("alice", "wrong"), "Invalid user name or password");
    assertRefused(authenticator, basic("nobody", "x"), "Invalid user name or password");
    // A user name with a DN special character is found by search
    assertEquals(authenticator.authenticate(basic("o,brien", "obrien-test-password")).getUser(), "o,brien");
  }

  @Test
  public void testEmptyPasswordIsRefusedWithoutABind() {
    LdapAuthenticator authenticator = authenticator(ldaps());
    _ldap._binds.set(0);
    assertRefused(authenticator, basic("alice", ""), "Invalid user name or password");
    // An empty password would be an unauthenticated bind, which directories accept: none is sent
    assertEquals(_ldap._binds.get(), 0);
  }

  @Test
  public void testFilterInjectionDoesNotMatchOtherEntries() {
    LdapAuthenticator authenticator = authenticator(ldaps());
    // Wildcards and filter syntax are escaped: none of these names finds alice (or any entry)
    for (String name : new String[]{"*", "al*", "alice)(uid=*", "*)(|(uid=*", "alice\\", "\u0000"}) {
      assertRefused(authenticator, basic(name, ALICE_PASSWORD), "Invalid user name or password");
    }
  }

  @Test
  public void testDirectBindWithDnPatternOverStartTls() {
    Map<String, Object> config = new HashMap<>();
    config.put("urls", "ldap://localhost:" + _ldapPort);
    config.put("start.tls", "true");
    config.put("truststore.path", _truststore.getAbsolutePath());
    config.put("truststore.password.alias", "ldap.truststore.password");
    config.put("bind.mode", "direct");
    config.put("user.dn.pattern", "uid={0},ou=people," + BASE);
    LdapAuthenticator authenticator = authenticator(config);
    PinotPrincipal principal = authenticator.authenticate(basic("alice", ALICE_PASSWORD));
    assertEquals(principal.getClaims().get("dn"), "uid=alice,ou=people," + BASE);
    // The name is escaped as a DN value
    assertEquals(authenticator.authenticate(basic("o,brien", "obrien-test-password")).getUser(), "o,brien");
    assertRefused(authenticator, basic("alice", "wrong"), "Invalid user name or password");
    assertRefused(authenticator, basic("alice,ou=services", ALICE_PASSWORD), "Invalid user name or password");
  }

  @Test
  public void testDirectBindWhereUsersMayOnlyReadTheirOwnEntry() {
    // Directory access rule: a user may read only their own entry. With a DN pattern the entry is read by its DN, so
    // a configured user search base (e.g. kept from search-then-bind) does not lock every user out
    Map<String, Object> config = ldaps();
    config.remove("bind.dn");
    config.remove("bind.password.alias");
    config.put("bind.mode", "direct");
    config.put("user.dn.pattern", "uid={0},ou=people," + BASE);
    _ldap._usersReadOnlySelf = true;
    try {
      LdapAuthenticator authenticator = authenticator(config);
      PinotPrincipal principal = authenticator.authenticate(basic("alice", ALICE_PASSWORD));
      assertEquals(principal.getUser(), "alice");
      assertEquals(principal.getClaims().get("dn"), "uid=alice,ou=people," + BASE);
      assertRefused(authenticator, basic("alice", "wrong"), "Invalid user name or password");
    } finally {
      _ldap._usersReadOnlySelf = false;
    }
  }

  @Test
  public void testDirectBindWithActiveDirectoryPrincipalName() {
    Map<String, Object> config = ldaps();
    config.remove("bind.dn");
    config.remove("bind.password.alias");
    config.put("bind.mode", "direct");
    config.put("user.dn.pattern", "{0}@example.com");
    config.put("user.search.filter", "(uid={0})");
    LdapAuthenticator authenticator = authenticator(config);
    assertEquals(authenticator.authenticate(basic("alice", ALICE_PASSWORD)).getClaims().get("dn"),
        "uid=alice,ou=people," + BASE);
    assertRefused(authenticator, basic("alice", "wrong"), "Invalid user name or password");
    // A principal-name pattern needs a search base to read the entry
    config.remove("user.search.base");
    expectThrows(IllegalArgumentException.class, () -> authenticator(config));
  }

  @Test
  public void testTransportRules() {
    Map<String, Object> plain = ldaps();
    plain.put("urls", "ldap://localhost:" + _ldapPort);
    plain.remove("truststore.path");
    // Passwords in clear text only when explicitly allowed (tests)
    IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> authenticator(plain));
    assertTrue(e.getMessage().contains("clear text"), e.getMessage());
    plain.put("allow.insecure", "true");
    assertEquals(authenticator(plain).authenticate(basic("alice", ALICE_PASSWORD)).getUser(), "alice");
    // The server certificate must be trusted: without the trust store the connection is refused, never accepted
    Map<String, Object> untrusted = ldaps();
    untrusted.remove("truststore.path");
    untrusted.remove("truststore.password.alias");
    assertRefused(authenticator(untrusted), basic("alice", ALICE_PASSWORD), "Directory unavailable");
    // Host name verification: a trusted certificate issued for another host is refused
    Map<String, Object> otherHost = ldaps();
    otherHost.put("urls", "ldaps://localhost:" + _otherHostPort);
    assertRefused(authenticator(otherHost), basic("alice", ALICE_PASSWORD), "Directory unavailable");
    Map<String, Object> mixed = ldaps();
    mixed.put("start.tls", "true");
    expectThrows(IllegalArgumentException.class, () -> authenticator(mixed));
    Map<String, Object> mixedSchemes = ldaps();
    mixedSchemes.put("allow.insecure", "true");
    mixedSchemes.put("urls", "ldaps://localhost:" + _ldapsPort + ",ldap://localhost:" + _ldapPort);
    expectThrows(IllegalArgumentException.class, () -> authenticator(mixedSchemes));
  }

  @Test
  public void testFailoverAndOutage()
      throws Exception {
    int closed;
    try (ServerSocket socket = new ServerSocket(0)) {
      closed = socket.getLocalPort();
    }
    Map<String, Object> config = ldaps();
    config.put("connect.timeout.ms", "1000");
    config.put("urls", "ldaps://localhost:" + closed + ",ldaps://localhost:" + _ldapsPort);
    assertEquals(authenticator(config).authenticate(basic("alice", ALICE_PASSWORD)).getUser(), "alice");
    config.put("urls", "ldaps://localhost:" + closed);
    assertRefused(authenticator(config), basic("alice", ALICE_PASSWORD), "Directory unavailable");
  }

  @Test
  public void testServiceUsersAndMalformedCredentials() {
    Map<String, Object> config = ldaps();
    config.put("service.users", "alice");
    LdapAuthenticator authenticator = authenticator(config);
    assertTrue(authenticator.authenticate(basic("alice", ALICE_PASSWORD)).isServiceAccount());
    assertRefused(authenticator, AuthCredential.parse("Basic !!!"), "Invalid user name or password");
    assertRefused(authenticator, AuthCredential.parse("Basic " + Base64.getEncoder().encodeToString(
        "no-colon".getBytes(StandardCharsets.UTF_8))), "Invalid user name or password");
    // Padding removed by a client is accepted
    String unpadded = Base64.getEncoder().withoutPadding().encodeToString(
        ("alice:" + ALICE_PASSWORD).getBytes(StandardCharsets.UTF_8));
    assertEquals(authenticator.authenticate(AuthCredential.parse("Basic " + unpadded)).getUser(), "alice");
  }

  @Test
  public void testDnWithCommaInAValue() {
    // Pinot's configuration drops the backslash of "\," (list separator): such a DN is refused at start with a hint,
    // and the equivalent hex escape \2C works
    Map<String, Object> config = ldaps();
    config.put("bind.dn", "cn=bind\\, sales,ou=Sales\\, East," + BASE);
    IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> authenticator(config));
    assertTrue(e.getMessage().contains("\\2C"), e.getMessage());
    config.put("bind.dn", "cn=bind\\2C sales,ou=Sales\\2C East," + BASE);
    Map<String, Object> secrets = new HashMap<>(config);
    LdapAuthenticator authenticator = new LdapAuthenticator();
    authenticator.init(new PinotConfiguration(secrets), alias -> alias.equals("ldap.bind.password")
        ? "sales-bind-test-password".toCharArray() : SECRETS.resolve(alias));
    assertEquals(authenticator.authenticate(basic("alice", ALICE_PASSWORD)).getUser(), "alice");
  }

  @Test
  public void testSelectedThroughTheSpi() {
    Map<String, Object> config = new HashMap<>();
    config.put("pinot.auth.method", "ldap");
    ldaps().forEach((k, v) -> config.put("pinot.auth.ldap." + k, v));
    PinotAuthenticator authenticator = AuthMethodSelector.create(new PinotConfiguration(config), SECRETS);
    assertTrue(authenticator instanceof LdapAuthenticator);
    assertEquals(authenticator.authenticate(basic("alice", ALICE_PASSWORD)).getUser(), "alice");
  }

  @Test
  public void testConfigurationErrors() {
    Map<String, Object> noUrls = ldaps();
    noUrls.remove("urls");
    expectThrows(IllegalArgumentException.class, () -> authenticator(noUrls));
    Map<String, Object> noBind = ldaps();
    noBind.remove("bind.dn");
    expectThrows(IllegalArgumentException.class, () -> authenticator(noBind));
    Map<String, Object> badMode = ldaps();
    badMode.put("bind.mode", "anonymous");
    expectThrows(IllegalArgumentException.class, () -> authenticator(badMode));
    Map<String, Object> badFilter = ldaps();
    badFilter.put("user.search.filter", "(uid=alice)");
    expectThrows(IllegalArgumentException.class, () -> authenticator(badFilter));
    Map<String, Object> badAlias = ldaps();
    badAlias.put("bind.password.alias", "missing");
    expectThrows(IllegalArgumentException.class, () -> authenticator(badAlias));
  }
}
