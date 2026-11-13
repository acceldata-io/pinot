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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [HttpTokenHandler] against a mock provider API, in the shape of an in-house provider with a validation API:
/// valid, invalid, expired, provider down, slow and oversized answers, retry, circuit breaker, enrich call, encoding
/// of the token in each position, and configuration errors.
public class HttpTokenHandlerTest {
  private static final long NOW = 1_800_000_000L;
  private static final SecretResolver SECRETS = alias -> {
    if (!alias.equals("idm.api.key")) {
      throw new IllegalArgumentException("Unknown alias " + alias);
    }
    return "k3y".toCharArray();
  };

  private static final class Answer {
    final int _status;
    final String _body;
    final long _delayMs;

    Answer(int status, String body, long delayMs) {
      _status = status;
      _body = body;
      _delayMs = delayMs;
    }
  }

  private HttpServer _server;
  private String _base;
  private final Map<String, Answer> _answers = new ConcurrentHashMap<>();
  private final List<String[]> _requests = new CopyOnWriteArrayList<>();

  @BeforeClass
  public void start()
      throws IOException {
    _server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    _server.setExecutor(Executors.newCachedThreadPool());
    _base = "http://127.0.0.1:" + _server.getAddress().getPort();
    _server.createContext("/", this::handle);
    _server.start();
  }

  @AfterClass
  public void stop() {
    _server.stop(0);
  }

  @BeforeMethod
  public void reset() {
    _answers.clear();
    _requests.clear();
  }

  private void handle(HttpExchange exchange)
      throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    _requests.add(new String[]{exchange.getRequestMethod(), exchange.getRequestURI().getRawPath()
        + (exchange.getRequestURI().getRawQuery() == null ? "" : "?" + exchange.getRequestURI().getRawQuery()),
        exchange.getRequestHeaders().getFirst("Authorization"), exchange.getRequestHeaders().getFirst("X-Client"),
        body});
    Answer answer = _answers.getOrDefault(exchange.getRequestURI().getPath(), new Answer(404, "{}", 0));
    if (answer._delayMs > 0) {
      try {
        Thread.sleep(answer._delayMs);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    byte[] bytes = answer._body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(answer._status, bytes.length == 0 ? -1 : bytes.length);
    if (bytes.length > 0) {
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(bytes);
      }
    }
    exchange.close();
  }

  private void answer(String path, int status, String body) {
    _answers.put(path, new Answer(status, body, 0));
  }

  private Map<String, Object> settings() {
    Map<String, Object> settings = new HashMap<>();
    settings.put("request.url", _base + "/v1/token/validate");
    settings.put("request.header.auth", "Authorization: Bearer ${token}");
    settings.put("request.header.client", "X-Client: ${client.id}");
    settings.put("client.id", "pinot");
    settings.put("success.condition", "$.valid == true");
    settings.put("map.user", "$.data.userId");
    settings.put("map.user.transform", "lower;strip-suffix:@example.com");
    settings.put("map.groups", "$.data.groups");
    settings.put("map.groups.transform", "strip-prefix:grp-");
    settings.put("map.expiresAt", "$.expiresAt");
    settings.put("map.attribute.tenant", "$.data.tid");
    settings.put("http.timeout.ms", "500");
    return settings;
  }

  private static HttpTokenHandler handler(Map<String, Object> settings) {
    HttpTokenHandler handler = new HttpTokenHandler();
    handler.init(new HandlerContext() {
      @Override
      public String getName() {
        return "idm";
      }

      @Override
      public PinotConfiguration getConfig() {
        return new PinotConfiguration(settings);
      }

      @Override
      public SecretResolver getSecretResolver() {
        return SECRETS;
      }

      @Override
      public Clock getClock() {
        return Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);
      }
    });
    return handler;
  }

  private static String valid(long expiresAt) {
    return "{\"valid\":true,\"data\":{\"userId\":\"Alice@Example.com\",\"groups\":\"grp-fin, grp-ops\",\"tid\":\"t1\"},"
        + "\"expiresAt\":" + expiresAt + "}";
  }

  @Test
  public void testValidToken() {
    answer("/v1/token/validate", 200, valid(NOW + 600));
    TokenIdentity identity = handler(settings()).validate("opaque-token");
    assertEquals(identity.getUser(), "alice");
    assertEquals(identity.getGroups(), Set.of("fin", "ops"));
    assertEquals(identity.getExpiresAt(), Instant.ofEpochSecond(NOW + 600));
    assertEquals(identity.getAttributes().get("tenant"), "t1");
    String[] request = _requests.get(0);
    assertEquals(request[0], "GET");
    assertEquals(request[2], "Bearer opaque-token");
    assertEquals(request[3], "pinot");
  }

  @Test
  public void testTokenEncodedForItsPosition() {
    answer("/v2/check", 200, valid(NOW + 600));
    Map<String, Object> settings = settings();
    settings.put("request.url", _base + "/v2/check?t=${token}");
    settings.put("request.method", "POST");
    settings.put("request.body", "{\"token\":\"${token}\",\"key\":\"${secret:idm.api.key}\"}");
    settings.remove("request.header.auth");
    String token = "a\"b c&d";
    handler(settings).validate(token);
    String[] request = _requests.get(0);
    assertEquals(request[1], "/v2/check?t=a%22b%20c%26d");
    assertEquals(request[4], "{\"token\":\"a\\\"b c&d\",\"key\":\"k3y\"}");

    settings.put("request.content.type", "application/x-www-form-urlencoded");
    settings.put("request.body", "token=${token}&client_id=${client.id}");
    _requests.clear();
    handler(settings).validate(token + "x");
    assertEquals(_requests.get(0)[4], "token=a%22b+c%26dx&client_id=pinot");
    // A line break cannot reach a header
    expectThrows(AuthenticationException.class, () -> handler(settings()).validate("evil\r\nX-Injected: 1"));
  }

  @Test
  public void testInvalidAndExpired() {
    HttpTokenHandler handler = handler(settings());
    answer("/v1/token/validate", 401, "{\"error\":\"invalid\"}");
    assertRejected(handler, "t1", "rejected by the identity provider (answered 401)");
    assertRejected(handler, "t1", "(cached)");
    assertEquals(_requests.size(), 1);
    answer("/v1/token/validate", 200, "{\"valid\":false}");
    assertRejected(handler, "t2", "success.condition");
    answer("/v1/token/validate", 200, valid(NOW - 10));
    assertRejected(handler, "t3", "expired");
    answer("/v1/token/validate", 200, "{\"valid\":true}");
    assertRejected(handler, "t4", "no user");
  }

  @Test
  public void testProviderFailures() {
    Map<String, Object> settings = settings();
    settings.put("breaker.failures", "100");
    HttpTokenHandler handler = handler(settings);
    // 5xx is retried once, then refused
    answer("/v1/token/validate", 503, "");
    assertRejected(handler, "a", "unavailable");
    assertEquals(_requests.size(), 2);
    // Slow answer: timeout, retried once
    _answers.put("/v1/token/validate", new Answer(200, valid(NOW + 600), 1500));
    assertRejected(handler, "b", "unavailable");
    // Oversized answer
    answer("/v1/token/validate", 200, "{\"valid\":true,\"pad\":\"" + "x".repeat(70_000) + "\"}");
    assertRejected(handler, "c", "unavailable");
    // Not JSON
    answer("/v1/token/validate", 200, "<html/>");
    assertRejected(handler, "d", "not JSON");
    // Provider down
    Map<String, Object> down = settings();
    down.put("request.url", "http://127.0.0.1:1/v1/token/validate");
    assertRejected(handler(down), "e", "unavailable");
    // Failures are not cached: the provider is back
    answer("/v1/token/validate", 200, valid(NOW + 600));
    assertEquals(handler.validate("a").getUser(), "alice");
  }

  @Test
  public void testCircuitBreaker() {
    Map<String, Object> settings = settings();
    settings.put("breaker.failures", "3");
    settings.put("retries", "0");
    HttpTokenHandler handler = handler(settings);
    answer("/v1/token/validate", 500, "");
    for (int i = 0; i < 3; i++) {
      assertRejected(handler, "t" + i, "answered 500");
    }
    answer("/v1/token/validate", 200, valid(NOW + 600));
    assertRejected(handler, "t9", "circuit breaker open");
    assertEquals(_requests.size(), 3);
  }

  @Test
  public void testEnrichCall() {
    answer("/v1/token/validate", 200, valid(NOW + 600));
    answer("/v1/users/alice/groups", 200, "{\"groups\":[\"grp-audit\"]}");
    Map<String, Object> settings = settings();
    settings.put("enrich.url", _base + "/v1/users/${user}/groups");
    settings.put("enrich.header.client", "X-Client: ${client.id}");
    settings.put("enrich.map.groups", "$.groups");
    TokenIdentity identity = handler(settings).validate("t");
    assertEquals(identity.getGroups(), Set.of("fin", "ops", "audit"));
    assertEquals(_requests.get(1)[1], "/v1/users/alice/groups");
  }

  @Test
  public void testConfigurationErrors() {
    Map<String, Object> typo = settings();
    typo.put("request.header.auth", "Authorization: Bearer ${tokn}");
    expectThrows(IllegalArgumentException.class, () -> handler(typo));
    Map<String, Object> noUser = settings();
    noUser.remove("map.user");
    expectThrows(IllegalArgumentException.class, () -> handler(noUser));
    Map<String, Object> badTransform = settings();
    badTransform.put("map.user.transform", "reverse");
    expectThrows(IllegalArgumentException.class, () -> handler(badTransform));
    Map<String, Object> missingSecret = settings();
    missingSecret.put("request.header.key", "X-Key: ${secret:missing}");
    expectThrows(IllegalArgumentException.class, () -> handler(missingSecret));
    Map<String, Object> badHeader = settings();
    badHeader.put("request.header.key", "no colon here");
    expectThrows(IllegalArgumentException.class, () -> handler(badHeader));
  }

  @Test
  public void testRoutingThroughTheRouter() {
    answer("/v1/token/validate", 200, valid(System.currentTimeMillis() / 1000 + 600));
    Map<String, Object> props = new HashMap<>();
    props.put("handlers", "idm");
    settings().forEach((key, value) -> props.put("handler.idm." + key, value));
    props.put("handler.idm.type", "http");
    props.put("handler.idm.issuer", "identityManager");
    OAuth2Authenticator authenticator = new OAuth2Authenticator();
    authenticator.init(new PinotConfiguration(props), SECRETS);
    try {
      assertEquals(authenticator.authenticate(AuthCredential.parse("Bearer opaque-1")).getUser(), "alice");
    } finally {
      authenticator.close();
    }
  }

  private static void assertRejected(HttpTokenHandler handler, String token, String reason) {
    AuthenticationException e = expectThrows(AuthenticationException.class, () -> handler.validate(token));
    assertTrue(e.getMessage().contains(reason), e.getMessage());
  }
}
