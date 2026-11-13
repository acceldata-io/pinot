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
package org.apache.pinot.plugin.auth.samples;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.samples.support.Jwts;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [CustomIdpTokenHandler] against a mock identity provider, with tokens shaped like an in-house provider's: HS512,
/// issuer `identityManager`, tenant and session ids, no user name and no audience.
public class CustomIdpTokenHandlerTest {
  static final String SECRET = "a-shared-signing-secret-of-at-least-64-bytes-for-hs512-0123456789abcdef";
  static final String ISSUER = "identityManager";
  static final long NOW = 1793874600L;

  private MockIdpServer _idp;

  @BeforeClass
  public void startIdp()
      throws Exception {
    _idp = new MockIdpServer();
  }

  @AfterClass
  public void stopIdp() {
    _idp.close();
  }

  @BeforeMethod
  public void resetIdp() {
    _idp.reset();
  }

  /// An HS-signed token with the provider's claim layout.
  static String token(String alg, String secret, String claimsJson) {
    Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    String headerJson = "{\"typ\":\"JWT\",\"alg\":\"" + alg + "\"}";
    String header = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
    String claims = encoder.encodeToString(claimsJson.getBytes(StandardCharsets.UTF_8));
    String input = header + "." + claims;
    String macName = alg.equals("none") ? "HmacSHA512" : Jwts.macName(alg);
    return input + "." + encoder.encodeToString(Jwts.sign(macName, secret.getBytes(StandardCharsets.UTF_8), input));
  }

  static String claims(String issuer, long iat, long exp) {
    return "{\"iss\":\"" + issuer + "\",\"version\":\"4.0\",\"tid\":\"8dc66d04-0000-4000-8000-000000000001\","
        + "\"sid\":\"3008d505-0000-4000-8000-000000000002\",\"iat\":" + iat + ",\"exp\":" + exp + "}";
  }

  static String validToken() {
    return token("HS512", SECRET, claims(ISSUER, NOW - 30, NOW + 3600));
  }

  private static Map<String, Object> localSettings() {
    Map<String, Object> settings = new HashMap<>();
    settings.put("issuer", ISSUER);
    settings.put("hmac.secret.alias", "idm.secret");
    settings.put("required.claims", "tid,sid,version=4.0");
    settings.put("user.claim", "sid");
    settings.put("http.timeout.ms", "1000");
    return settings;
  }

  private static CustomIdpTokenHandler handler(Map<String, Object> settings) {
    CustomIdpTokenHandler handler = new CustomIdpTokenHandler();
    handler.init(new TestContext(settings, Map.of("idm.secret", SECRET, "idm.client.secret", "pinot-client-secret",
        "idm.previous.secret", "the-previous-signing-secret"),
        Instant.ofEpochSecond(NOW)));
    return handler;
  }

  @Test
  public void testLocalVerificationOnly() {
    TokenIdentity identity = handler(localSettings()).validate(validToken());
    assertEquals(identity.getUser(), "3008d505-0000-4000-8000-000000000002");
    assertEquals(identity.getIssuer(), ISSUER);
    assertEquals(identity.getExpiresAt(), Instant.ofEpochSecond(NOW + 3600));
    assertEquals(identity.getAttributes().get("tid"), "8dc66d04-0000-4000-8000-000000000001");
    assertEquals(identity.getAttributes().get("handler"), "idm");
    assertTrue(_idp._requests.isEmpty());
  }

  @Test
  public void testValidationAndUserInfoCalls() {
    _idp.answer("/v1/validate", 200, "{\"valid\":true}");
    _idp.answer("/v1/userinfo", 200, "{\"data\":{\"userId\":\"alice\",\"roles\":[\"analysts\",\"ops\"]},"
        + "\"scope\":\"pinot.read pinot.write\"}");
    _idp.answer("/v1/groups", 200, "{\"groups\":\"finance, audit\"}");
    Map<String, Object> settings = localSettings();
    settings.put("validation.url", _idp.url("/v1/validate"));
    settings.put("validation.active.field", "valid");
    settings.put("userinfo.url", _idp.url("/v1/userinfo"));
    settings.put("groups.url", _idp.url("/v1/groups"));
    settings.put("user.field", "data.userId");
    settings.put("groups.field", "groups");
    settings.put("scopes.field", "scope");
    String token = validToken();
    TokenIdentity identity = handler(settings).validate(token);
    assertEquals(identity.getUser(), "alice");
    assertEquals(identity.getGroups(), Set.of("finance", "audit"));
    assertEquals(identity.getScopes(), Set.of("pinot.read", "pinot.write"));
    assertEquals(_idp._requests.size(), 3);
    for (MockIdpServer.Request request : _idp._requests) {
      assertEquals(request._authorization, "Bearer " + token, request._path);
    }
    assertFalse(identity.getAttributes().containsValue(token));
  }

  @Test
  public void testFormStyleValidationSendsClientCredentials() {
    _idp.answer("/introspect", 200, "{\"active\":true,\"username\":\"bob\"}");
    Map<String, Object> settings = localSettings();
    settings.remove("hmac.secret.alias");
    settings.put("validation.url", _idp.url("/introspect"));
    settings.put("validation.style", "form");
    settings.put("validation.active.field", "active");
    settings.put("client.id", "pinot");
    settings.put("client.secret.alias", "idm.client.secret");
    settings.put("user.field", "username");
    String token = validToken();
    assertEquals(handler(settings).validate(token).getUser(), "bob");
    MockIdpServer.Request request = _idp._requests.get(0);
    assertEquals(request._method, "POST");
    assertEquals(request._body, "token=" + token);
    assertEquals(request._authorization, "Basic " + Base64.getEncoder().encodeToString(
        "pinot:pinot-client-secret".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void testTokensOfOthersAreLeftToOtherHandlers() {
    CustomIdpTokenHandler handler = handler(localSettings());
    assertNull(handler.validate(token("HS512", SECRET, claims("https://accounts.google.com", NOW, NOW + 60))));
    assertNull(handler.validate("ya29.an-opaque-access-token"));
    assertNull(handler.validate("not.a.jwt"));
  }

  @Test
  public void testInvalidTokensAreRejected() {
    CustomIdpTokenHandler handler = handler(localSettings());
    assertRejected(handler, token("HS512", "another-secret", claims(ISSUER, NOW - 30, NOW + 3600)), "bad signature");
    assertRejected(handler, token("HS256", SECRET, claims(ISSUER, NOW - 30, NOW + 3600)), "not accepted");
    assertRejected(handler, token("none", SECRET, claims(ISSUER, NOW - 30, NOW + 3600)), "not accepted");
    // Shaped like the provider's sample token, whose exp lies before its iat
    assertRejected(handler, token("HS512", SECRET, claims(ISSUER, 1793874573L, 1793849773L)), "expired");
    assertRejected(handler, token("HS512", SECRET, claims(ISSUER, NOW + 600, NOW + 3600)), "issued in the future");
    assertRejected(handler, token("HS512", SECRET, "{\"iss\":\"" + ISSUER + "\",\"version\":\"4.0\",\"sid\":\"s\","
        + "\"exp\":" + (NOW + 60) + "}"), "claim 'tid'");
    assertRejected(handler, token("HS512", SECRET, "{\"iss\":\"" + ISSUER + "\",\"tid\":\"t\",\"sid\":\"s\","
        + "\"version\":\"4.0\"}"), "no expiry");
    // Within the clock skew an expired token still passes
    assertEquals(handler.validate(token("HS512", SECRET, claims(ISSUER, NOW - 600, NOW - 30))).getUser(),
        "3008d505-0000-4000-8000-000000000002");
  }

  @Test
  public void testSecretRotation() {
    String oldToken = token("HS512", "the-previous-signing-secret", claims(ISSUER, NOW - 30, NOW + 3600));
    assertRejected(handler(localSettings()), oldToken, "bad signature");
    Map<String, Object> settings = localSettings();
    settings.put("hmac.previous.secret.alias", "idm.previous.secret");
    CustomIdpTokenHandler handler = handler(settings);
    assertEquals(handler.validate(oldToken).getUser(), "3008d505-0000-4000-8000-000000000002");
    assertEquals(handler.validate(validToken()).getUser(), "3008d505-0000-4000-8000-000000000002");
    assertRejected(handler, token("HS512", "a-third-secret", claims(ISSUER, NOW - 30, NOW + 3600)), "bad signature");
  }

  @Test
  public void testProviderAnswers() {
    Map<String, Object> settings = localSettings();
    settings.put("validation.url", _idp.url("/v1/validate"));
    settings.put("validation.active.field", "valid");
    CustomIdpTokenHandler handler = handler(settings);
    String token = validToken();

    _idp.answer("/v1/validate", 401, "{\"error\":\"session revoked\"}");
    assertRejected(handler, token, "rejected by the identity provider");
    _idp.answer("/v1/validate", 200, "{\"valid\":false}");
    assertRejected(handler, token, "not active");
    _idp.answer("/v1/validate", 503, "");
    assertRejected(handler, token, "unavailable");
    _idp.answer("/v1/validate", 200, "<html>login</html>");
    assertRejected(handler, token, "unavailable");
    _idp.answer("/v1/validate", 302, "");
    assertRejected(handler, token, "unavailable");
    // Slow provider: the call times out (1 s) and the request is refused
    _idp.answer("/v1/validate", 200, "{\"valid\":true}", 3000);
    long start = System.currentTimeMillis();
    assertRejected(handler, token, "unavailable");
    assertTrue(System.currentTimeMillis() - start < 2500);
  }

  @Test
  public void testProviderDown() {
    Map<String, Object> settings = localSettings();
    // Nothing listens on port 1
    settings.put("validation.url", "http://127.0.0.1:1/v1/validate");
    assertRejected(handler(settings), validToken(), "unavailable");
  }

  @Test
  public void testOpaqueTokens() {
    _idp.answer("/v1/validate", 200, "{\"user\":\"carol\",\"expiresAt\":" + (NOW + 120) + "}");
    Map<String, Object> settings = localSettings();
    settings.remove("hmac.secret.alias");
    settings.put("accept.opaque", "true");
    settings.put("validation.url", _idp.url("/v1/validate"));
    settings.put("user.field", "user");
    settings.put("expires.field", "expiresAt");
    TokenIdentity identity = handler(settings).validate("opaque-session-token");
    assertEquals(identity.getUser(), "carol");
    assertEquals(identity.getExpiresAt(), Instant.ofEpochSecond(NOW + 120));

    _idp.answer("/v1/validate", 200, "{\"user\":\"carol\",\"expiresAt\":" + (NOW - 3600) + "}");
    assertRejected(handler(settings), "opaque-session-token", "expired");
  }

  @Test
  public void testUnsafeConfigurationsAreRefused() {
    Map<String, Object> unverified = localSettings();
    unverified.remove("hmac.secret.alias");
    expectThrows(IllegalArgumentException.class, () -> handler(unverified));

    Map<String, Object> asymmetric = localSettings();
    asymmetric.put("algorithms", "HS512,RS256");
    expectThrows(IllegalArgumentException.class, () -> handler(asymmetric));

    Map<String, Object> opaqueWithoutValidation = localSettings();
    opaqueWithoutValidation.put("accept.opaque", "true");
    expectThrows(IllegalArgumentException.class, () -> handler(opaqueWithoutValidation));

    Map<String, Object> unknownSecret = localSettings();
    unknownSecret.put("hmac.secret.alias", "missing");
    expectThrows(IllegalArgumentException.class, () -> handler(unknownSecret));

    Map<String, Object> noIssuer = localSettings();
    noIssuer.remove("issuer");
    expectThrows(IllegalArgumentException.class, () -> handler(noIssuer));
  }

  private static void assertRejected(CustomIdpTokenHandler handler, String token, String reason) {
    AuthenticationException e = expectThrows(AuthenticationException.class, () -> handler.validate(token));
    assertTrue(e.getMessage().contains(reason), e.getMessage());
    assertFalse(e.getMessage().contains(token));
    assertTrue(e.getChallenge().startsWith("Bearer realm=\"pinot\""));
  }
}
