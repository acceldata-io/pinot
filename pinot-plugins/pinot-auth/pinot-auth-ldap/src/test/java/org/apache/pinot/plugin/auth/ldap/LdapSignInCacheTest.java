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

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.apache.pinot.plugin.auth.ldap.EmbeddedLdap.BASE;
import static org.apache.pinot.plugin.auth.ldap.EmbeddedLdap.basic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// Sign-in caching, failure cache and throttle of [LdapAuthenticator] ([LdapSignInCache]): fewer directory calls,
/// service accounts riding through outages, and no account lockout under client retry loops.
public class LdapSignInCacheTest {
  private static final String ALICE_DN = "uid=alice,ou=people," + BASE;
  private static final String SVC_DN = "uid=svc-pinot,ou=people," + BASE;

  private EmbeddedLdap _ldap;
  private final AtomicLong _now = new AtomicLong(1_800_000_000_000L);
  private final Clock _clock = new Clock() {
    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return Instant.ofEpochMilli(_now.get());
    }
  };

  @BeforeMethod
  public void startServer()
      throws Exception {
    _ldap = new EmbeddedLdap(
        "dn: " + ALICE_DN, "objectClass: inetOrgPerson", "uid: alice", "cn: Alice", "sn: A", "userPassword: alice-pw",
        "",
        "dn: " + SVC_DN, "objectClass: inetOrgPerson", "uid: svc-pinot", "cn: svc", "sn: s", "userPassword: svc-pw");
  }

  @AfterMethod
  public void stopServer() {
    _ldap.close();
  }

  private LdapAuthenticator authenticator(String... settings) {
    Map<String, Object> config = _ldap.ldaps();
    config.put("service.users", "svc-pinot");
    for (int i = 0; i < settings.length; i += 2) {
      config.put(settings[i], settings[i + 1]);
    }
    LdapAuthenticator authenticator = new LdapAuthenticator();
    authenticator.init(new PinotConfiguration(config), EmbeddedLdap.SECRETS, _clock);
    return authenticator;
  }

  private void advance(long seconds) {
    _now.addAndGet(seconds * 1000);
  }

  private static void refused(LdapAuthenticator authenticator, String user, String password) {
    expectThrows(AuthenticationException.class, () -> authenticator.authenticate(basic(user, password)));
  }

  @Test
  public void testSuccessCacheTtls() {
    LdapAuthenticator authenticator = authenticator();
    authenticator.authenticate(basic("alice", "alice-pw"));
    authenticator.authenticate(basic("ALICE", "alice-pw"));
    assertEquals(_ldap.binds(ALICE_DN), 1);
    advance(299);
    authenticator.authenticate(basic("alice", "alice-pw"));
    assertEquals(_ldap.binds(ALICE_DN), 1);
    advance(2);
    authenticator.authenticate(basic("alice", "alice-pw"));
    assertEquals(_ldap.binds(ALICE_DN), 2);
    // Service accounts: 1 hour by default
    assertTrue(authenticator.authenticate(basic("svc-pinot", "svc-pw")).isServiceAccount());
    advance(3500);
    authenticator.authenticate(basic("svc-pinot", "svc-pw"));
    assertEquals(_ldap.binds(SVC_DN), 1);
    advance(101);
    authenticator.authenticate(basic("svc-pinot", "svc-pw"));
    assertEquals(_ldap.binds(SVC_DN), 2);
    // Another password is never answered from the cache
    refused(authenticator, "alice", "not-alice-pw");
    assertEquals(_ldap.binds(ALICE_DN), 3);
  }

  @Test
  public void testServiceAccountRidesThroughADirectoryOutage() {
    LdapAuthenticator authenticator = authenticator();
    authenticator.authenticate(basic("svc-pinot", "svc-pw"));
    authenticator.authenticate(basic("alice", "alice-pw"));
    _ldap.close();
    advance(600);
    // Within its hour the service account keeps signing in; alice's 5 minutes are over and she is refused
    assertEquals(authenticator.authenticate(basic("svc-pinot", "svc-pw")).getUser(), "svc-pinot");
    AuthenticationException e = expectThrows(AuthenticationException.class,
        () -> authenticator.authenticate(basic("alice", "alice-pw")));
    assertEquals(e.getMessage(), "Directory unavailable");
  }

  @Test
  public void testRepeatedWrongPasswordDoesNotReachTheDirectory() {
    LdapAuthenticator authenticator = authenticator();
    for (int i = 0; i < 20; i++) {
      refused(authenticator, "alice", "wrong");
    }
    assertEquals(_ldap.binds(ALICE_DN), 1);
    // After the failure cache period the directory is asked again
    advance(31);
    refused(authenticator, "alice", "wrong");
    assertEquals(_ldap.binds(ALICE_DN), 2);
    // The right password is not affected by the failure cache
    assertEquals(authenticator.authenticate(basic("alice", "alice-pw")).getUser(), "alice");
  }

  @Test
  public void testThrottleKeepsTheAccountBelowTheLockoutThreshold() {
    // The directory locks an account after 3 wrong passwords, as an Active Directory policy would
    _ldap._lockoutThreshold = 3;
    LdapAuthenticator authenticator = authenticator("failure.max.attempts", "2");
    // A client cycling through stale passwords
    for (int i = 0; i < 30; i++) {
      refused(authenticator, "alice", "stale-" + (i % 4));
    }
    assertEquals(_ldap.binds(ALICE_DN), 2);
    assertFalse(_ldap.locked(ALICE_DN));
    // Throttled: refused without a bind, also with the right password, until the window has passed
    refused(authenticator, "alice", "alice-pw");
    assertEquals(_ldap.binds(ALICE_DN), 2);
    advance(61);
    assertEquals(authenticator.authenticate(basic("alice", "alice-pw")).getUser(), "alice");
    assertFalse(_ldap.locked(ALICE_DN));
  }

  @Test
  public void testWithoutTheThrottleTheDirectoryLocksTheAccount() {
    // The same retry loop with a throttle above the directory's threshold: the account is locked
    _ldap._lockoutThreshold = 3;
    LdapAuthenticator authenticator = authenticator("failure.max.attempts", "50", "failure.cache.seconds", "0");
    for (int i = 0; i < 30; i++) {
      refused(authenticator, "alice", "stale-" + (i % 4));
    }
    assertTrue(_ldap.locked(ALICE_DN));
    refused(authenticator, "alice", "alice-pw");
  }

  @Test
  public void testEmptyPasswordAndInvalidSettings() {
    LdapAuthenticator authenticator = authenticator();
    refused(authenticator, "alice", "");
    assertEquals(_ldap.binds(ALICE_DN), 0);
    expectThrows(IllegalArgumentException.class, () -> authenticator("failure.max.attempts", "0"));
  }
}
