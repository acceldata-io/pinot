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
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [IntrospectionTokenHandler] against a mock RFC 7662 endpoint: active / inactive answers, provider failures and
/// timeouts, client authentication styles, discovery, the positive and negative cache, and routing through the router.
public class IntrospectionTokenHandlerTest {
  private static final long NOW = 1_800_000_000L;
  private static final SecretResolver SECRETS = alias -> {
    if (!alias.equals("pinot.introspection.secret")) {
      throw new IllegalArgumentException("Unknown alias " + alias);
    }
    return "s3cret".toCharArray();
  };

  private HttpServer _server;
  private String _base;
  private final List<String[]> _requests = new CopyOnWriteArrayList<>();
  private final AtomicReference<Integer> _status = new AtomicReference<>(200);
  private final AtomicReference<String> _body = new AtomicReference<>("{}");
  private volatile long _delayMs;

  @BeforeClass
  public void start()
      throws IOException {
    _server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    _server.setExecutor(Executors.newCachedThreadPool());
    _base = "http://127.0.0.1:" + _server.getAddress().getPort();
    _server.createContext("/realms/test/.well-known/openid-configuration", exchange -> reply(exchange, 200,
        "{\"issuer\":\"" + _base + "/realms/test\",\"introspection_endpoint\":\"" + _base + "/introspect\"}"));
    _server.createContext("/introspect", exchange -> {
      String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      _requests.add(new String[]{exchange.getRequestHeaders().getFirst("Authorization"), body});
      if (_delayMs > 0) {
        try {
          Thread.sleep(_delayMs);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      reply(exchange, _status.get(), _body.get());
    });
    _server.start();
  }

  @AfterClass
  public void stop() {
    _server.stop(0);
  }

  @BeforeMethod
  public void reset() {
    _requests.clear();
    _status.set(200);
    _body.set("{}");
    _delayMs = 0;
  }

  private static void reply(HttpExchange exchange, int status, String body)
      throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
    if (bytes.length > 0) {
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(bytes);
      }
    }
    exchange.close();
  }

  private Map<String, Object> settings() {
    Map<String, Object> settings = new HashMap<>();
    settings.put("introspection.url", _base + "/introspect");
    settings.put("client.id", "pinot");
    settings.put("client.secret.alias", "pinot.introspection.secret");
    settings.put("http.timeout.ms", "500");
    return settings;
  }

  private static IntrospectionTokenHandler handler(Map<String, Object> settings, Clock clock) {
    IntrospectionTokenHandler handler = new IntrospectionTokenHandler();
    handler.init(new HandlerContext() {
      @Override
      public String getName() {
        return "kc";
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
        return clock;
      }
    });
    return handler;
  }

  private static Clock at(long epochSeconds) {
    return Clock.fixed(Instant.ofEpochSecond(epochSeconds), ZoneOffset.UTC);
  }

  private static String active(String user, long exp) {
    return "{\"active\":true,\"username\":\"" + user + "\",\"sub\":\"f81d4fae\",\"scope\":\"openid pinot.read\","
        + "\"groups\":[\"analysts\",\"ops\"],\"aud\":[\"pinot\",\"account\"],\"exp\":" + exp + "}";
  }

  @Test
  public void testActiveToken() {
    _body.set(active("alice", NOW + 600));
    TokenIdentity identity = handler(settings(), at(NOW)).validate("opaque-token-1");
    assertEquals(identity.getUser(), "alice");
    assertEquals(identity.getGroups(), Set.of("analysts", "ops"));
    assertEquals(identity.getScopes(), Set.of("openid", "pinot.read"));
    assertEquals(identity.getExpiresAt(), Instant.ofEpochSecond(NOW + 600));
    String[] request = _requests.get(0);
    assertEquals(request[0], "Basic " + Base64.getEncoder().encodeToString("pinot:s3cret".getBytes(
        StandardCharsets.UTF_8)));
    assertEquals(request[1], "token=opaque-token-1&token_type_hint=access_token");
  }

  @Test
  public void testPostClientAuthAndSubFallback() {
    _body.set("{\"active\":true,\"sub\":\"svc-ingest\",\"exp\":" + (NOW + 600) + "}");
    Map<String, Object> settings = settings();
    settings.put("client.auth", "post");
    assertEquals(handler(settings, at(NOW)).validate("t").getUser(), "svc-ingest");
    assertEquals(_requests.get(0)[0], null);
    assertEquals(_requests.get(0)[1], "token=t&token_type_hint=access_token&client_id=pinot&client_secret=s3cret");
  }

  @Test
  public void testRejections() {
    IntrospectionTokenHandler handler = handler(settings(), at(NOW));
    _body.set("{\"active\":false}");
    assertRejected(handler, "a", "not active");
    _body.set(active("alice", NOW - 1));
    assertRejected(handler, "b", "expired");
    _body.set("{\"active\":true,\"exp\":" + (NOW + 60) + "}");
    assertRejected(handler, "c", "no 'username' or 'sub'");

    Map<String, Object> withAudience = settings();
    withAudience.put("audiences", "other-api");
    _body.set(active("alice", NOW + 600));
    assertRejected(handler(withAudience, at(NOW)), "d", "aud");
  }

  @Test
  public void testProviderFailuresAreNeverCached() {
    IntrospectionTokenHandler handler = handler(settings(), at(NOW));
    _status.set(503);
    assertRejected(handler, "t", "unavailable");
    _status.set(401);
    assertRejected(handler, "t", "refuses Pinot's client credentials");
    _status.set(200);
    _body.set("<html/>");
    assertRejected(handler, "t", "not a JSON object");
    _body.set(active("alice", NOW + 600));
    _delayMs = 1500;
    assertRejected(handler, "t", "unavailable");
    _delayMs = 0;
    // The provider is back: nothing of the failures was cached
    assertEquals(handler.validate("t").getUser(), "alice");
    assertEquals(_requests.size(), 5);
  }

  @Test
  public void testCache() {
    AtomicReference<Instant> now = new AtomicReference<>(Instant.ofEpochSecond(NOW));
    Clock clock = new Clock() {
      @Override
      public ZoneOffset getZone() {
        return ZoneOffset.UTC;
      }

      @Override
      public Clock withZone(java.time.ZoneId zone) {
        return this;
      }

      @Override
      public Instant instant() {
        return now.get();
      }
    };
    IntrospectionTokenHandler handler = handler(settings(), clock);
    // Active token expiring in 30 s: cached for 30 s (exp), not the full 60 s
    _body.set(active("alice", NOW + 30));
    handler.validate("good");
    handler.validate("good");
    assertEquals(_requests.size(), 1);
    now.set(Instant.ofEpochSecond(NOW + 31));
    _body.set(active("alice", NOW + 600));
    handler.validate("good");
    assertEquals(_requests.size(), 2);

    // Inactive token: refused from the cache for 10 s, then asked again
    _body.set("{\"active\":false}");
    assertRejected(handler, "bad", "not active");
    assertRejected(handler, "bad", "not active (cached)");
    assertEquals(_requests.size(), 3);
    now.set(Instant.ofEpochSecond(NOW + 42));
    assertRejected(handler, "bad", "not active");
    assertEquals(_requests.size(), 4);
  }

  @Test
  public void testDiscoveryAndRouting() {
    _body.set(active("alice", System.currentTimeMillis() / 1000 + 600));
    Map<String, Object> props = new HashMap<>();
    props.put("handlers", "kc");
    props.put("handler.kc.type", "introspection");
    props.put("handler.kc.issuer", _base + "/realms/test");
    props.put("handler.kc.client.id", "pinot");
    props.put("handler.kc.client.secret.alias", "pinot.introspection.secret");
    OAuth2Authenticator authenticator = new OAuth2Authenticator();
    authenticator.init(new PinotConfiguration(props), SECRETS);
    try {
      // Opaque token: no issuer to route by, still checked by the introspection handler
      PinotPrincipal principal = authenticator.authenticate(AuthCredential.parse("Bearer opaque-abc"));
      assertEquals(principal.getUser(), "alice");
      assertTrue(principal.getGroups().contains("analysts"));
      // Endpoint taken from the discovery document
      assertFalse(_requests.isEmpty());
    } finally {
      authenticator.close();
    }
    Map<String, Object> noEndpoint = settings();
    noEndpoint.remove("introspection.url");
    expectThrows(IllegalArgumentException.class, () -> handler(noEndpoint, at(NOW)));
    Map<String, Object> noSecret = settings();
    noSecret.put("client.secret.alias", "missing");
    expectThrows(IllegalArgumentException.class, () -> handler(noSecret, at(NOW)));
  }

  private static void assertRejected(IntrospectionTokenHandler handler, String token, String reason) {
    AuthenticationException e = expectThrows(AuthenticationException.class, () -> handler.validate(token));
    assertTrue(e.getMessage().contains(reason), e.getMessage());
    assertTrue(e.getChallenge().startsWith("Bearer realm=\"pinot\""));
  }
}
