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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthMethodSelector;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.plugin.auth.spi.SingleMethodAuthentication;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


public class OAuth2AuthenticatorTest {
  private static final String AUD = "pinot";
  private static final SecretResolver SECRETS = alias -> {
    if ("hs.secret".equals(alias)) {
      return "a-shared-secret-of-at-least-32-bytes!!".toCharArray();
    }
    throw new IllegalArgumentException("unknown alias " + alias);
  };

  private TestIdentityProvider _idp;
  private TestIdentityProvider _otherIdp;

  @BeforeClass
  public void setUp()
      throws Exception {
    _idp = new TestIdentityProvider();
    _otherIdp = new TestIdentityProvider();
  }

  @AfterClass
  public void tearDown() {
    _idp.close();
    _otherIdp.close();
  }

  private static Map<String, Object> handler(String name, TestIdentityProvider idp, boolean discovery) {
    Map<String, Object> props = new HashMap<>();
    props.put("handler." + name + ".type", "jwt");
    props.put("handler." + name + ".issuer", idp._issuer);
    props.put("handler." + name + ".audiences", AUD + ",other");
    if (!discovery) {
      props.put("handler." + name + ".jwks.url", idp.jwksUrl());
    }
    return props;
  }

  private OAuth2Authenticator authenticator(Map<String, Object> props) {
    OAuth2Authenticator authenticator = new OAuth2Authenticator();
    authenticator.init(new PinotConfiguration(props), SECRETS);
    return authenticator;
  }

  private OAuth2Authenticator single(Map<String, Object> extra) {
    Map<String, Object> props = handler("main", _idp, false);
    props.put("handlers", "main");
    props.putAll(extra);
    return authenticator(props);
  }

  private static PinotPrincipal auth(OAuth2Authenticator authenticator, String token) {
    return authenticator.authenticate(AuthCredential.parse("Bearer " + token));
  }

  private static void assertRejected(OAuth2Authenticator authenticator, String token, String reasonPart) {
    AuthenticationException e = expectThrows(AuthenticationException.class, () -> auth(authenticator, token));
    assertTrue(e.getMessage().contains(reasonPart), "expected '" + reasonPart + "' in: " + e.getMessage());
    assertTrue(e.getChallenge().startsWith("Bearer realm=\"pinot\""), e.getChallenge());
    assertFalse(e.getMessage().contains(token), "message must not contain the token");
  }

  @Test
  public void testValidTokenGivesPrincipal()
      throws Exception {
    PinotPrincipal principal = auth(single(Map.of()), _idp.sign(_idp.claims(AUD).build()));
    assertEquals(principal.getUser(), "alice");
    assertEquals(principal.getGroups(), Set.of("analysts", "ops"));
    assertEquals(principal.getMethod(), AuthMethod.OAUTH2);
    assertEquals(principal.getClaims().get("iss"), _idp._issuer);
  }

  @Test
  public void testEveryClaimFailure()
      throws Exception {
    OAuth2Authenticator authenticator = single(Map.of());
    long now = System.currentTimeMillis();
    assertRejected(authenticator, _idp.sign(_idp.claims("someone-else").build()), "aud");
    assertRejected(authenticator, _idp.sign(new JWTClaimsSet.Builder(_idp.claims(AUD).build()).audience((String) null)
        .build()), "aud");
    assertRejected(authenticator, _idp.sign(_idp.claims(AUD).expirationTime(new Date(now - 120_000)).build()),
        "Expired");
    assertRejected(authenticator, _idp.sign(_idp.claims(AUD).expirationTime(null).build()), "exp");
    assertRejected(authenticator, _idp.sign(_idp.claims(AUD).notBeforeTime(new Date(now + 600_000)).build()),
        "before");
    // Within the 60 s default skew
    auth(authenticator, _idp.sign(_idp.claims(AUD).notBeforeTime(new Date(now + 30_000)).build()));
    auth(authenticator, _idp.sign(_idp.claims(AUD).expirationTime(new Date(now - 30_000)).build()));
    assertRejected(authenticator, _idp.sign(_idp.claims(AUD).subject(null).build()), "sub");
    assertRejected(authenticator, _idp.signWithForeignKey(_idp.claims(AUD).build()), "Invalid token");
    // A JWT without iss cannot be routed to a provider
    assertRejected(authenticator, "eyJhbGciOiJSUzI1NiJ9.e30.c2ln", "not recognised");
  }

  @Test
  public void testIssuerIsCheckedByTheHandler()
      throws Exception {
    JwtTokenHandler handler = new JwtTokenHandler();
    Map<String, Object> props = new HashMap<>();
    props.put("issuer", "https://expected.example.com");
    props.put("audiences", AUD);
    props.put("jwks.url", _idp.jwksUrl());
    handler.init(new SimpleHandlerContext("direct", new PinotConfiguration(props), SECRETS));
    AuthenticationException e = expectThrows(AuthenticationException.class,
        () -> handler.validate(_idp.sign(_idp.claims(AUD).build())));
    assertTrue(e.getMessage().contains("iss"), e.getMessage());
  }

  @Test
  public void testAlgorithmRules()
      throws Exception {
    OAuth2Authenticator rsaOnly = single(Map.of("handler.main.algorithms", "RS256"));
    assertRejected(rsaOnly, _idp.signEs256(_idp.claims(AUD).build()), "Invalid token");
    // The default allow-list includes ES256
    auth(single(Map.of()), _idp.signEs256(_idp.claims(AUD).build()));
    // Unsigned tokens and HS256 signed with the public key (algorithm confusion) are rejected
    assertRejected(single(Map.of()), TestIdentityProvider.unsigned(_idp.claims(AUD).build()), "Invalid token");
    assertRejected(single(Map.of()), _idp.signHs256WithPublicKey(_idp.claims(AUD).build()), "Invalid token");
    // 'none' and HS without a shared secret cannot even be configured
    assertThrows(IllegalArgumentException.class, () -> single(Map.of("handler.main.algorithms", "none")));
    assertThrows(IllegalArgumentException.class, () -> single(Map.of("handler.main.algorithms", "HS256")));
    assertThrows(IllegalArgumentException.class, () -> single(Map.of("handler.main.algorithms", "RS256,HS256",
        "handler.main.hmac.secret.alias", "hs.secret")));
    // HS256 with an explicit shared secret works, and only with that secret
    OAuth2Authenticator hs = single(Map.of("handler.main.algorithms", "HS256", "handler.main.hmac.secret.alias",
        "hs.secret"));
    auth(hs, TestIdentityProvider.signHs256(_idp.claims(AUD).build(), "a-shared-secret-of-at-least-32-bytes!!"));
    assertRejected(hs, TestIdentityProvider.signHs256(_idp.claims(AUD).build(), "another-secret-of-at-least-32-bytes!"),
        "Invalid token");
  }

  @Test
  public void testRequiredClaimsTypeAndIdTokens()
      throws Exception {
    OAuth2Authenticator domain = single(Map.of("handler.main.required.claims", "hd=example.com"));
    auth(domain, _idp.sign(_idp.claims(AUD).claim("hd", "example.com").build()));
    assertRejected(domain, _idp.sign(_idp.claims(AUD).claim("hd", "evil.com").build()), "hd");
    assertRejected(domain, _idp.sign(_idp.claims(AUD).build()), "hd");

    OAuth2Authenticator accessTokensOnly = single(Map.of("handler.main.token.type", "at+jwt"));
    auth(accessTokensOnly, _idp.sign(_idp.claims(AUD).build(), new JOSEObjectType("at+jwt")));
    assertRejected(accessTokensOnly, _idp.sign(_idp.claims(AUD).build()), "Invalid token");

    String idToken = _idp.sign(_idp.claims(AUD).claim("nonce", "n-1").build());
    assertRejected(single(Map.of()), idToken, "ID tokens");
    auth(single(Map.of("handler.main.accept.id.tokens", "true")), idToken);
  }

  @Test
  public void testKeyRotationAndRefetchRateLimit()
      throws Exception {
    TestIdentityProvider idp = new TestIdentityProvider();
    try {
      Map<String, Object> props = handler("rot", idp, false);
      props.put("handlers", "rot");
      OAuth2Authenticator authenticator = authenticator(props);
      auth(authenticator, idp.sign(idp.claims(AUD).build()));
      int fetches = idp._jwksFetches.get();
      // New key: the unknown kid triggers one refetch and the token is accepted
      idp.rotate("k2");
      auth(authenticator, idp.sign(idp.claims(AUD).build()));
      assertEquals(idp._jwksFetches.get(), fetches + 1);
      // Cached afterwards
      auth(authenticator, idp.sign(idp.claims(AUD).build()));
      assertEquals(idp._jwksFetches.get(), fetches + 1);
      // A second unknown kid right away is not refetched (at most once per 60 s), so it is rejected
      idp.rotate("k3");
      assertRejected(authenticator, idp.sign(idp.claims(AUD).build()), "signing key not published");
      assertEquals(idp._jwksFetches.get(), fetches + 1);
    } finally {
      idp.close();
    }
  }

  @Test
  public void testMultiIssuerRoutingAndSizeLimit()
      throws Exception {
    Map<String, Object> props = handler("a", _idp, false);
    props.putAll(handler("b", _otherIdp, true));
    props.put("handlers", "a,b");
    OAuth2Authenticator authenticator = authenticator(props);
    assertEquals(auth(authenticator, _idp.sign(_idp.claims(AUD).build())).getClaims().get("iss"), _idp._issuer);
    assertEquals(auth(authenticator, _otherIdp.sign(_otherIdp.claims(AUD).subject("bob").build())).getUser(), "bob");
    // A token of provider A carrying provider B's issuer goes to B and fails B's signature check
    assertRejected(authenticator, _idp.sign(_idp.claims(AUD).issuer(_otherIdp._issuer).build()), "Invalid token");
    assertRejected(authenticator, _idp.sign(_idp.claims(AUD).issuer("https://unknown.example.com").build()),
        "issuer is not configured");
    assertRejected(authenticator, "opaque-token-value", "not recognised");
    String huge = _idp.sign(_idp.claims(AUD).claim("pad", "x".repeat(17_000)).build());
    assertRejected(authenticator, huge, "larger than");
  }

  @Test
  public void testDiscovery()
      throws Exception {
    Map<String, Object> props = handler("d", _idp, true);
    props.put("handlers", "d");
    auth(authenticator(props), _idp.sign(_idp.claims(AUD).build()));
    _idp._discoveryIssuer = "https://impostor.example.com";
    try {
      IllegalStateException e = expectThrows(IllegalStateException.class, () -> authenticator(props));
      assertTrue(e.getMessage().contains("impostor"), e.getMessage());
    } finally {
      _idp._discoveryIssuer = _idp._issuer;
    }
    Map<String, Object> missing = new HashMap<>(props);
    missing.remove("handler.d.audiences");
    assertThrows(IllegalArgumentException.class, () -> authenticator(missing));
  }

  @Test
  public void testSelectedThroughTheSpi()
      throws Exception {
    Map<String, Object> props = new HashMap<>();
    props.put("pinot.auth.method", "oauth2");
    props.put("pinot.auth.oauth2.handlers", "main");
    handler("main", _idp, false).forEach((k, v) -> props.put("pinot.auth.oauth2." + k, v));
    PinotAuthenticator authenticator = AuthMethodSelector.create(new PinotConfiguration(props), SECRETS);
    assertTrue(authenticator instanceof OAuth2Authenticator);
    SingleMethodAuthentication auth = new SingleMethodAuthentication(authenticator);
    assertEquals(auth.authenticate("Bearer " + _idp.sign(_idp.claims(AUD).build())).getUser(), "alice");
    AuthenticationException basic = expectThrows(AuthenticationException.class,
        () -> auth.authenticate("Basic YWRtaW46c2VjcmV0"));
    assertEquals(basic.getChallenge(), "Bearer realm=\"pinot\"");
  }
}
