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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// Token shapes of real providers: Google ID tokens (RS256, issuer https://accounts.google.com, client id as audience,
/// email / hd claims) and an HS512 token of an in-house identity manager without `aud` or `sub`.
public class ProviderTokenShapesTest {
  private static final String GOOGLE_ISSUER = "https://accounts.google.com";
  private static final String HS_SECRET = "in-house-identity-manager-shared-secret-at-least-64-bytes-long-0123456789";
  private static final SecretResolver SECRETS = alias -> {
    if ("idm.secret".equals(alias)) {
      return HS_SECRET.toCharArray();
    }
    throw new IllegalArgumentException("unknown alias " + alias);
  };

  private TestIdentityProvider _idp;

  @BeforeClass
  public void setUp()
      throws Exception {
    _idp = new TestIdentityProvider();
  }

  @AfterClass
  public void tearDown() {
    _idp.close();
  }

  private static OAuth2Authenticator authenticator(Map<String, Object> handlerProps) {
    Map<String, Object> props = new HashMap<>();
    props.put("handlers", "p");
    handlerProps.forEach((k, v) -> props.put("handler.p." + k, v));
    OAuth2Authenticator authenticator = new OAuth2Authenticator();
    authenticator.init(new PinotConfiguration(props), SECRETS);
    return authenticator;
  }

  private static PinotPrincipal auth(OAuth2Authenticator authenticator, String token) {
    return authenticator.authenticate(AuthCredential.parse("Bearer " + token));
  }

  /// HS512, iss "identityManager", no aud, no sub; the user comes from a configured claim.
  private static String inHouseToken(Map<String, Object> extraClaims, String secret)
      throws Exception {
    long now = System.currentTimeMillis() / 1000;
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer("identityManager").claim("version", "4.0")
        .claim("tid", "8dc66d04-8299-4362-8848-adf3b3ca1d13").claim("sid", "3008d505-cc17-4ec6-b519-a15b3bc77909")
        .issueTime(new Date(now * 1000)).expirationTime(new Date((now + 600) * 1000));
    extraClaims.forEach(claims::claim);
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS512).type(
        com.nimbusds.jose.JOSEObjectType.JWT).build(), claims.build());
    jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
    return jwt.serialize();
  }

  @Test
  public void testInHouseHs512TokenWithoutAudience()
      throws Exception {
    Map<String, Object> config = new HashMap<>();
    config.put("issuer", "identityManager");
    config.put("algorithms", "HS512");
    config.put("hmac.secret.alias", "idm.secret");
    config.put("require.audience", "false");
    config.put("user.claim", "tid");
    OAuth2Authenticator authenticator = authenticator(config);
    PinotPrincipal principal = auth(authenticator, inHouseToken(Map.of(), HS_SECRET));
    assertEquals(principal.getUser(), "8dc66d04-8299-4362-8848-adf3b3ca1d13");
    assertEquals(principal.getClaims().get("sid"), "3008d505-cc17-4ec6-b519-a15b3bc77909");

    // Wrong secret, expired token, and HS256 instead of HS512 are rejected
    expectThrows(AuthenticationException.class,
        () -> auth(authenticator, inHouseToken(Map.of(), HS_SECRET.replace('0', 'x'))));
    String expired = inHouseToken(Map.of("exp", (System.currentTimeMillis() / 1000) - 3600), HS_SECRET);
    expectThrows(AuthenticationException.class, () -> auth(authenticator, expired));
    expectThrows(AuthenticationException.class,
        () -> auth(authenticator, TestIdentityProvider.signHs256(new JWTClaimsSet.Builder().issuer("identityManager")
            .claim("tid", "t").expirationTime(new Date(System.currentTimeMillis() + 60_000)).build(), HS_SECRET)));

    // Without require.audience=false the provider must name audiences
    config.remove("require.audience");
    assertThrows(IllegalArgumentException.class, () -> authenticator(config));
    // Configured audiences are always enforced, even with require.audience=false
    config.put("require.audience", "false");
    config.put("audiences", "pinot");
    AuthenticationException e = expectThrows(AuthenticationException.class,
        () -> auth(authenticator(config), inHouseToken(Map.of(), HS_SECRET)));
    assertTrue(e.getMessage().contains("aud"), e.getMessage());
  }

  @Test
  public void testGoogleShapedIdToken()
      throws Exception {
    Map<String, Object> config = new HashMap<>();
    config.put("issuer", _idp._issuer);
    config.put("jwks.url", _idp.jwksUrl());
    config.put("audiences", "1234567890-abc.apps.googleusercontent.com");
    config.put("accept.id.tokens", "true");
    config.put("user.claim", "email");
    config.put("required.claims", "hd=example.com,email_verified=true");
    OAuth2Authenticator authenticator = authenticator(config);
    JWTClaimsSet.Builder google = _idp.claims("1234567890-abc.apps.googleusercontent.com").subject("1078812345")
        .claim("azp", "1234567890-abc.apps.googleusercontent.com").claim("email", "alice@example.com")
        .claim("email_verified", true).claim("hd", "example.com").claim("at_hash", "HK6E_P6Dh8Y93mRNtsDB1Q")
        .claim("name", "Alice").claim("groups", List.of());
    assertEquals(auth(authenticator, _idp.sign(google.build())).getUser(), "alice@example.com");
    // Another Workspace domain, an unverified email, or another client id are rejected
    expectThrows(AuthenticationException.class,
        () -> auth(authenticator, _idp.sign(google.claim("hd", "gmail.com").build())));
    google.claim("hd", "example.com");
    expectThrows(AuthenticationException.class,
        () -> auth(authenticator, _idp.sign(google.claim("email_verified", false).build())));
    google.claim("email_verified", true);
    expectThrows(AuthenticationException.class,
        () -> auth(authenticator, _idp.sign(google.audience("other-client.apps.googleusercontent.com").build())));
  }

  /// Uses Google's live discovery document and keys; skipped without internet access.
  @Test
  public void testLiveGoogleDiscoveryAndKeys()
      throws Exception {
    String googleKid;
    try {
      googleKid = JWKSet.load(new URL("https://www.googleapis.com/oauth2/v3/certs")).getKeys().get(0).getKeyID();
    } catch (Exception e) {
      throw new SkipException("Google endpoints not reachable: " + e.getMessage());
    }
    Map<String, Object> config = new HashMap<>();
    config.put("issuer", GOOGLE_ISSUER);
    config.put("audiences", "1234567890-abc.apps.googleusercontent.com");
    config.put("accept.id.tokens", "true");
    config.put("user.claim", "email");
    // Discovery resolves Google's key set; init fails if the document or keys cannot be used
    OAuth2Authenticator authenticator = authenticator(config);
    // A token claiming Google's issuer and a real Google key id, but signed with another key, is rejected
    RSAKey forger = new RSAKeyGenerator(2048).keyID(googleKid).generate();
    SignedJWT forged = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(googleKid).build(),
        new JWTClaimsSet.Builder().issuer(GOOGLE_ISSUER).audience("1234567890-abc.apps.googleusercontent.com")
            .subject("1").claim("email", "mallory@example.com")
            .expirationTime(new Date(System.currentTimeMillis() + 300_000)).build());
    forged.sign(new RSASSASigner(forger));
    AuthenticationException e = expectThrows(AuthenticationException.class,
        () -> auth(authenticator, forged.serialize()));
    assertTrue(e.getMessage().contains("Invalid token"), e.getMessage());
  }
}
