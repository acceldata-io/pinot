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
import org.apache.pinot.plugin.auth.spi.AccessToken;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [CustomIdpTokenSource] against a mock token endpoint.
public class CustomIdpTokenSourceTest {
  private static final Instant NOW = Instant.ofEpochSecond(1793874600L);
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

  private CustomIdpTokenSource source(Map<String, Object> extra) {
    Map<String, Object> settings = new HashMap<>();
    settings.put("token.url", _idp.url("/v1/token"));
    settings.put("client.id", "pinot-service");
    settings.put("client.secret.alias", "idm.client.secret");
    settings.put("http.timeout.ms", "1000");
    settings.putAll(extra);
    CustomIdpTokenSource source = new CustomIdpTokenSource();
    source.init(new TestContext(settings, Map.of("idm.client.secret", "s3cr\"et"), NOW));
    return source;
  }

  @Test
  public void testFormRequest() {
    _idp.answer("/v1/token", 200, "{\"access_token\":\"tok-1\",\"expires_in\":600}");
    AccessToken token = source(Map.of("scope", "pinot.service")).fetch();
    assertEquals(token.getToken(), "tok-1");
    assertEquals(token.getExpiresAt(), NOW.plusSeconds(600));
    assertFalse(token.toString().contains("tok-1"));
    MockIdpServer.Request request = _idp._requests.get(0);
    assertEquals(request._body, "grant_type=client_credentials&scope=pinot.service");
    assertEquals(request._authorization, "Basic " + Base64.getEncoder().encodeToString(
        "pinot-service:s3cr\"et".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void testJsonRequestAndCustomFields() {
    _idp.answer("/v1/token", 200, "{\"data\":{\"token\":\"tok-2\",\"validTill\":" + (NOW.getEpochSecond() + 90)
        + "}}");
    AccessToken token = source(Map.of("request.format", "json", "token.field", "data.token", "expires.at.field",
        "data.validTill")).fetch();
    assertEquals(token.getToken(), "tok-2");
    assertEquals(token.getExpiresAt(), NOW.plusSeconds(90));
    assertEquals(_idp._requests.get(0)._body, "{\"clientId\":\"pinot-service\",\"clientSecret\":\"s3cr\\\"et\"}");
  }

  @Test
  public void testDefaultLifetime() {
    _idp.answer("/v1/token", 200, "{\"access_token\":\"tok-3\"}");
    assertEquals(source(Map.of()).fetch().getExpiresAt(), NOW.plusSeconds(300));
  }

  @Test
  public void testFailures() {
    CustomIdpTokenSource source = source(Map.of());
    _idp.answer("/v1/token", 401, "{\"error\":\"invalid_client\",\"echo\":\"s3cr\\\"et\"}");
    IllegalStateException e = expectThrows(IllegalStateException.class, source::fetch);
    assertTrue(e.getMessage().contains("401"));
    assertFalse(e.getMessage().contains("s3cr"));
    _idp.answer("/v1/token", 200, "{\"token_type\":\"bearer\"}");
    expectThrows(IllegalStateException.class, source::fetch);
    _idp.answer("/v1/token", 200, "{}", 3000);
    expectThrows(IllegalStateException.class, source::fetch);
    // A missing secret fails at start, not at the first outbound call
    Map<String, Object> settings = new HashMap<>();
    settings.put("token.url", _idp.url("/v1/token"));
    settings.put("client.id", "pinot-service");
    settings.put("client.secret.alias", "missing");
    expectThrows(IllegalArgumentException.class,
        () -> new CustomIdpTokenSource().init(new TestContext(settings, Map.of(), NOW)));
  }
}
