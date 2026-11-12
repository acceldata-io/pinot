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
package org.apache.pinot.plugin.auth.spi;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


public class SingleMethodAuthenticationTest {
  /// Instances created per stub class, to prove only the configured method is instantiated.
  static final Map<String, AtomicInteger> CREATED = new ConcurrentHashMap<>();

  /// Stub authenticator: accepts the credential value "good", rejects anything else.
  public abstract static class StubAuthenticator implements PinotAuthenticator {
    PinotConfiguration _config;

    protected StubAuthenticator() {
      CREATED.computeIfAbsent(getClass().getSimpleName(), k -> new AtomicInteger()).incrementAndGet();
    }

    @Override
    public void init(PinotConfiguration config, SecretResolver secretResolver) {
      _config = config;
    }

    @Override
    public PinotPrincipal authenticate(AuthCredential credential) {
      if (!"good".equals(credential.getValue())) {
        throw new AuthenticationException("Credential rejected", AuthenticationException.challengeFor(getMethod()));
      }
      return new PinotPrincipal("alice", Set.of("analysts"), getMethod(), false, Map.of());
    }
  }

  public static class StubBasic extends StubAuthenticator {
    @Override
    public AuthMethod getMethod() {
      return AuthMethod.BASIC;
    }
  }

  public static class StubOAuth2 extends StubAuthenticator {
    @Override
    public AuthMethod getMethod() {
      return AuthMethod.OAUTH2;
    }
  }

  public static class StubLdap extends StubAuthenticator {
    @Override
    public AuthMethod getMethod() {
      return AuthMethod.LDAP;
    }
  }

  private static final SecretResolver NO_SECRETS = alias -> {
    throw new IllegalArgumentException("no secret " + alias);
  };

  @BeforeMethod
  public void reset() {
    CREATED.clear();
  }

  private static PinotConfiguration config(String method) {
    Map<String, Object> props = new HashMap<>();
    if (method != null) {
      props.put("pinot.auth.method", method);
    }
    props.put("pinot.auth.basic.authenticator.class", StubBasic.class.getName());
    props.put("pinot.auth.oauth2.authenticator.class", StubOAuth2.class.getName());
    props.put("pinot.auth.ldap.authenticator.class", StubLdap.class.getName());
    props.put("pinot.auth.oauth2.issuer", "https://idp.example.com");
    return new PinotConfiguration(props);
  }

  @Test
  public void testMethodValues() {
    assertEquals(AuthMethod.fromConfigValue(" OAuth2 "), AuthMethod.OAUTH2);
    assertEquals(AuthMethod.fromConfigValue("basic"), AuthMethod.BASIC);
    assertEquals(AuthMethod.fromConfigValue("LDAP"), AuthMethod.LDAP);
    assertThrows(IllegalArgumentException.class, () -> AuthMethod.fromConfigValue("kerberos"));
    assertThrows(IllegalArgumentException.class, () -> AuthMethod.fromConfigValue(null));
    assertEquals(AuthMethod.OAUTH2.getScheme(), "Bearer");
    assertEquals(AuthMethod.LDAP.getScheme(), "Basic");
  }

  @Test
  public void testUnsetMethodMeansNoAuthenticator() {
    assertNull(AuthMethodSelector.getConfiguredMethod(config(null)));
    assertNull(AuthMethodSelector.create(config(null), NO_SECRETS));
    assertNull(AuthMethodSelector.create(config("  "), NO_SECRETS));
    assertTrue(CREATED.isEmpty());
  }

  @Test
  public void testOnlyTheConfiguredMethodIsCreated() {
    for (AuthMethod method : AuthMethod.values()) {
      CREATED.clear();
      PinotAuthenticator authenticator = AuthMethodSelector.create(config(method.getConfigValue()), NO_SECRETS);
      assertEquals(authenticator.getMethod(), method);
      assertEquals(CREATED.size(), 1, "created: " + CREATED);
      assertEquals(CREATED.values().iterator().next().get(), 1);
    }
  }

  @Test
  public void testMethodSettingsArePassedWithoutPrefix() {
    StubOAuth2 authenticator = (StubOAuth2) AuthMethodSelector.create(config("oauth2"), NO_SECRETS);
    assertEquals(authenticator._config.getProperty("issuer"), "https://idp.example.com");
  }

  @Test
  public void testDefaultClassesAndFailures() {
    PinotConfiguration plain = new PinotConfiguration(Map.of("pinot.auth.method", "oauth2"));
    assertEquals(AuthMethodSelector.getAuthenticatorClass(plain, AuthMethod.OAUTH2),
        AuthMethodSelector.DEFAULT_OAUTH2_AUTHENTICATOR);
    // The method module is not on this classpath: a clear error, no fallback to another method
    IllegalStateException missing = expectThrows(IllegalStateException.class,
        () -> AuthMethodSelector.create(plain, NO_SECRETS));
    assertTrue(missing.getMessage().contains("oauth2 authenticator"), missing.getMessage());
    // An implementation of another method than configured is refused
    PinotConfiguration wrongClass = new PinotConfiguration(Map.of("pinot.auth.method", "ldap",
        "pinot.auth.ldap.authenticator.class", StubBasic.class.getName()));
    IllegalStateException mismatch = expectThrows(IllegalStateException.class,
        () -> AuthMethodSelector.create(wrongClass, NO_SECRETS));
    assertTrue(mismatch.getMessage().contains("implements method basic"), mismatch.getMessage());
    assertThrows(IllegalArgumentException.class,
        () -> AuthMethodSelector.create(new PinotConfiguration(Map.of("pinot.auth.method", "both")), NO_SECRETS));
  }

  @Test
  public void testWrongCredentialTypeIs401WithTheMethodsChallenge() {
    SingleMethodAuthentication oauth = new SingleMethodAuthentication(new StubOAuth2());
    assertEquals(oauth.authenticate("Bearer good").getUser(), "alice");
    assertEquals(oauth.authenticate("bearer good").getMethod(), AuthMethod.OAUTH2);
    for (String header : new String[]{null, "", "Bearer", "Bearer   ", "Basic Z29vZA==", "Negotiate good"}) {
      AuthenticationException e = expectThrows(AuthenticationException.class, () -> oauth.authenticate(header));
      assertEquals(e.getChallenge(), "Bearer realm=\"pinot\"", String.valueOf(header));
    }
    AuthenticationException rejected = expectThrows(AuthenticationException.class,
        () -> oauth.authenticate("Bearer bad"));
    assertEquals(rejected.getChallenge(), "Bearer realm=\"pinot\"");
    assertFalse(rejected.getMessage().contains("bad"), "message must not echo the credential");

    for (PinotAuthenticator basicLike : List.of(new StubBasic(), new StubLdap())) {
      SingleMethodAuthentication auth = new SingleMethodAuthentication(basicLike);
      assertEquals(auth.authenticate("Basic good").getMethod(), basicLike.getMethod());
      AuthenticationException e = expectThrows(AuthenticationException.class, () -> auth.authenticate("Bearer good"));
      assertEquals(e.getChallenge(), "Basic realm=\"pinot\"");
      assertTrue(e.getMessage().contains("not accepted"), e.getMessage());
    }
  }

  @Test
  public void testAuthenticatorMustReturnItsOwnMethod() {
    PinotAuthenticator lying = new StubOAuth2() {
      @Override
      public PinotPrincipal authenticate(AuthCredential credential) {
        return new PinotPrincipal("alice", Set.of(), AuthMethod.BASIC, false, Map.of());
      }
    };
    assertThrows(IllegalStateException.class, () -> new SingleMethodAuthentication(lying).authenticate("Bearer x"));
  }

  @Test
  public void testClusterUsesOneMethod() {
    Map<String, String> zk = new ConcurrentHashMap<>();
    ClusterSettingStore store = new ClusterSettingStore() {
      @Override
      public String putIfAbsent(String key, String value) {
        String previous = zk.putIfAbsent(key, value);
        return previous == null ? value : previous;
      }

      @Override
      public String get(String key) {
        return zk.get(key);
      }
    };
    AuthMethodConsistency.verify(AuthMethod.OAUTH2, store, "Controller_a_9000");
    assertEquals(store.get(AuthMethodConsistency.CLUSTER_METHOD_KEY), "oauth2");
    AuthMethodConsistency.verify(AuthMethod.OAUTH2, store, "Broker_b_8099");
    IllegalStateException e = expectThrows(IllegalStateException.class,
        () -> AuthMethodConsistency.verify(AuthMethod.LDAP, store, "Server_c_8098"));
    assertTrue(e.getMessage().contains("Server_c_8098") && e.getMessage().contains("cluster uses oauth2"),
        e.getMessage());
    zk.put(AuthMethodConsistency.CLUSTER_METHOD_KEY, "garbage");
    assertThrows(IllegalStateException.class, () -> AuthMethodConsistency.verify(AuthMethod.OAUTH2, store, "x"));
  }

  @Test
  public void testCredentialAndPrincipalValues() {
    assertNull(AuthCredential.parse("Bearer"));
    AuthCredential credential = AuthCredential.parse("  Bearer   abc.def  ");
    assertEquals(credential.getScheme(), "Bearer");
    assertEquals(credential.getValue(), "abc.def");
    assertFalse(credential.toString().contains("abc"));

    PinotPrincipal principal = new PinotPrincipal("svc", Set.of("b", "a"), AuthMethod.OAUTH2, true,
        Map.of("token", "secret"));
    assertTrue(principal.isServiceAccount());
    assertEquals(List.copyOf(principal.getGroups()), List.of("a", "b"));
    assertFalse(principal.toString().contains("secret"));
    assertThrows(UnsupportedOperationException.class, () -> principal.getGroups().add("c"));
    assertThrows(IllegalArgumentException.class,
        () -> new PinotPrincipal(" ", Set.of(), AuthMethod.BASIC, false, Map.of()));
    assertSame(new PinotPrincipal("a", Set.of(), AuthMethod.LDAP, false, Map.of()).getMethod(), AuthMethod.LDAP);
  }
}
