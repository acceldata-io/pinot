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

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [GoogleTokenHandler] against a mock token-info endpoint answering like Google's.
public class GoogleTokenHandlerTest {
  private static final Instant NOW = Instant.ofEpochSecond(1793874600L);
  private static final String CLIENT = "1234-abc.apps.googleusercontent.com";
  private MockIdpServer _google;

  @BeforeClass
  public void startGoogle()
      throws Exception {
    _google = new MockIdpServer();
  }

  @AfterClass
  public void stopGoogle() {
    _google.close();
  }

  private GoogleTokenHandler handler(String hostedDomain) {
    Map<String, Object> settings = new HashMap<>();
    settings.put("client.ids", CLIENT + ",other-client");
    settings.put("tokeninfo.url", _google.url("/tokeninfo"));
    if (hostedDomain != null) {
      settings.put("hosted.domain", hostedDomain);
    }
    GoogleTokenHandler handler = new GoogleTokenHandler();
    handler.init(new TestContext(settings, Map.of(), NOW));
    return handler;
  }

  private static String info(String azp, String email, String verified, long expiresIn) {
    return "{\"azp\":\"" + azp + "\",\"aud\":\"" + azp + "\",\"sub\":\"1077\",\"scope\":\"openid "
        + "https://www.googleapis.com/auth/userinfo.email\",\"exp\":\"" + (NOW.getEpochSecond() + expiresIn)
        + "\",\"expires_in\":\"" + expiresIn + "\",\"email\":\"" + email + "\",\"email_verified\":\"" + verified
        + "\",\"access_type\":\"online\"}";
  }

  @Test
  public void testValidAccessToken() {
    _google.answer("/tokeninfo", 200, info(CLIENT, "alice@example.com", "true", 1800));
    TokenIdentity identity = handler("example.com").validate("ya29.a0-access-token");
    assertEquals(identity.getUser(), "alice@example.com");
    assertEquals(identity.getExpiresAt(), NOW.plusSeconds(1800));
    assertEquals(identity.getScopes(), Set.of("openid", "https://www.googleapis.com/auth/userinfo.email"));
    assertEquals(_google._requests.get(_google._requests.size() - 1)._body, "access_token=ya29.a0-access-token");
  }

  @Test
  public void testRejections() {
    GoogleTokenHandler handler = handler("example.com");
    assertNull(handler.validate("eyJhbGciOiJSUzI1NiJ9.e30.sig"));
    _google.answer("/tokeninfo", 200, info("someone-elses-app", "alice@example.com", "true", 1800));
    assertRejected(handler, "another application");
    _google.answer("/tokeninfo", 200, info(CLIENT, "alice@example.com", "false", 1800));
    assertRejected(handler, "no verified email");
    _google.answer("/tokeninfo", 200, info(CLIENT, "mallory@example.com.evil.test", "true", 1800));
    assertRejected(handler, "domain");
    _google.answer("/tokeninfo", 200, info(CLIENT, "alice@example.com", "true", 0));
    assertRejected(handler, "expired");
    _google.answer("/tokeninfo", 400, "{\"error\":\"invalid_token\"}");
    assertRejected(handler, "rejected by Google");
    _google.answer("/tokeninfo", 500, "");
    assertRejected(handler, "unavailable");
  }

  private static void assertRejected(GoogleTokenHandler handler, String reason) {
    AuthenticationException e = expectThrows(AuthenticationException.class,
        () -> handler.validate("ya29.a0-access-token"));
    assertTrue(e.getMessage().contains(reason), e.getMessage());
  }
}
