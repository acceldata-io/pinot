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

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.pinot.common.auth.AuthProviderUtils;
import org.apache.pinot.plugin.auth.spi.AccessToken;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenSource;
import org.apache.pinot.spi.auth.AuthProvider;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// Outbound tokens for Pinot's own calls: [CachingTokenSource] refresh and outage rules, [ClientCredentialsTokenSource]
/// against a mock token endpoint, and [OAuthAuthProvider] built by Pinot's own `AuthProviderUtils` from an outbound
/// namespace.
public class OAuthAuthProviderTest {
  private HttpServer _server;
  private String _base;
  private final List<String[]> _requests = new CopyOnWriteArrayList<>();
  private final AtomicInteger _status = new AtomicInteger(200);
  private final AtomicInteger _issued = new AtomicInteger();

  @BeforeClass
  public void start()
      throws IOException {
    _server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    _server.setExecutor(Executors.newCachedThreadPool());
    _base = "http://127.0.0.1:" + _server.getAddress().getPort();
    _server.createContext("/realms/test/.well-known/openid-configuration", exchange -> reply(exchange, 200,
        "{\"token_endpoint\":\"" + _base + "/token\"}"));
    _server.createContext("/token", exchange -> {
      _requests.add(new String[]{exchange.getRequestHeaders().getFirst("Authorization"),
          new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)});
      int status = _status.get();
      reply(exchange, status, status == 200
          ? "{\"access_token\":\"tok-" + _issued.incrementAndGet() + "\",\"expires_in\":300,\"token_type\":\"Bearer\"}"
          : "{\"error\":\"unavailable\"}");
    });
    _server.createContext("/google/token", exchange -> {
      String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      _requests.add(new String[]{null, body});
      long exp = Instant.now().getEpochSecond() + 3600;
      String idToken = "eyJhbGciOiJSUzI1NiJ9." + Base64.getUrlEncoder().withoutPadding().encodeToString(
          ("{\"aud\":\"pinot-client\",\"exp\":" + exp + "}").getBytes(StandardCharsets.UTF_8)) + ".c2ln";
      reply(exchange, 200, "{\"id_token\":\"" + idToken + "\"}");
    });
    _server.createContext("/custom/token", exchange -> {
      _requests.add(new String[]{exchange.getRequestHeaders().getFirst("X-Api-Key"),
          new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)});
      reply(exchange, 200, "{\"data\":{\"jwt\":\"custom-" + _issued.incrementAndGet() + "\",\"ttl\":120}}");
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
    _issued.set(0);
    OAuthAuthProvider.clearSharedSources();
  }

  private static void reply(HttpExchange exchange, int status, String body)
      throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  /// A clock the test moves.
  private static final class TestClock extends Clock {
    final AtomicReference<Instant> _now = new AtomicReference<>(Instant.ofEpochSecond(1_800_000_000L));

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
      return _now.get();
    }

    void advance(long seconds) {
      _now.set(_now.get().plusSeconds(seconds));
    }
  }

  /// A source issuing tokens valid for 100 s, failing on demand.
  private static final class ScriptedSource implements OAuthTokenSource {
    final TestClock _clock;
    final AtomicInteger _fetches = new AtomicInteger();
    volatile boolean _fail;
    volatile CountDownLatch _block;

    ScriptedSource(TestClock clock) {
      _clock = clock;
    }

    @Override
    public void init(HandlerContext context) {
    }

    @Override
    public AccessToken fetch() {
      int n = _fetches.incrementAndGet();
      if (_block != null) {
        try {
          _block.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      if (_fail) {
        throw new IllegalStateException("token endpoint down");
      }
      return new AccessToken("t" + n, _clock.instant().plusSeconds(100));
    }
  }

  @Test
  public void testRefreshAt80PercentAndOutageUntilExpiry() {
    TestClock clock = new TestClock();
    ScriptedSource source = new ScriptedSource(clock);
    CachingTokenSource cache = new CachingTokenSource("test", source, clock, 1);
    assertEquals(cache.get(), "t1");
    clock.advance(79);
    assertEquals(cache.get(), "t1");
    assertEquals(source._fetches.get(), 1);
    clock.advance(2);
    assertEquals(cache.get(), "t2");

    // The token endpoint goes down: the current token is used until it expires (3 attempts per refresh)
    source._fail = true;
    clock.advance(85);
    assertEquals(cache.get(), "t2");
    assertEquals(source._fetches.get(), 2 + CachingTokenSource.ATTEMPTS);
    clock.advance(20);
    expectThrows(IllegalStateException.class, cache::get);
    // Back up: a new token
    source._fail = false;
    assertTrue(cache.get().startsWith("t"));
  }

  @Test
  public void testOneFetchInFlight()
      throws Exception {
    TestClock clock = new TestClock();
    ScriptedSource source = new ScriptedSource(clock);
    CachingTokenSource cache = new CachingTokenSource("test", source, clock, 1);
    assertEquals(cache.get(), "t1");
    clock.advance(90);
    // While one caller refreshes, the others keep the still-valid token without waiting
    source._block = new CountDownLatch(1);
    ExecutorService executor = Executors.newFixedThreadPool(8);
    try {
      Future<String> refresher = executor.submit(cache::get);
      Thread.sleep(200);
      for (int i = 0; i < 20; i++) {
        assertEquals(executor.submit(cache::get).get(1, TimeUnit.SECONDS), "t1");
      }
      source._block.countDown();
      assertEquals(refresher.get(5, TimeUnit.SECONDS), "t2");
      assertEquals(source._fetches.get(), 2);
    } finally {
      executor.shutdownNow();
    }
  }

  private Map<String, Object> namespace(String prefix) {
    Map<String, Object> config = new HashMap<>();
    config.put(prefix + ".provider.class", OAuthAuthProvider.class.getName());
    config.put(prefix + ".source", "client_credentials");
    config.put(prefix + ".issuer", _base + "/realms/test");
    config.put(prefix + ".client.id", "pinot-service");
    config.put(prefix + ".client.secret", "s3cret");
    config.put(prefix + ".scope", "pinot.internal");
    return config;
  }

  @Test
  public void testProviderFromOutboundNamespaces() {
    Map<String, Object> config = namespace("controller.broker.auth");
    config.putAll(namespace("controller.server.admin.auth"));
    PinotConfiguration pinotConfig = new PinotConfiguration(config);
    AuthProvider broker = AuthProviderUtils.extractAuthProvider(pinotConfig, "controller.broker.auth");
    AuthProvider server = AuthProviderUtils.extractAuthProvider(pinotConfig, "controller.server.admin.auth");
    assertTrue(broker instanceof OAuthAuthProvider);
    assertEquals(broker.getRequestHeaders(), Map.of("Authorization", "Bearer tok-1"));
    // Same settings: one token for the process
    assertEquals(server.getTaskToken(), "Bearer tok-1");
    assertEquals(_requests.size(), 1);
    assertEquals(_requests.get(0)[0], ProviderHttp.basic("pinot-service", "s3cret".toCharArray()));
    assertEquals(_requests.get(0)[1], "grant_type=client_credentials&scope=pinot.internal");
  }

  @Test
  public void testClientCredentialsErrors() {
    Map<String, Object> config = namespace("task.auth");
    config.put("task.auth.client.auth", "post");
    _status.set(401);
    AuthProvider provider = AuthProviderUtils.extractAuthProvider(new PinotConfiguration(config), "task.auth");
    IllegalStateException e = expectThrows(IllegalStateException.class, provider::getTaskToken);
    assertTrue(e.getMessage().contains("no valid token"), e.getMessage());
    assertTrue(_requests.get(0)[1].contains("client_id=pinot-service&client_secret=s3cret"));
    // A missing secret fails when the provider is created, not at the first internal call
    Map<String, Object> noSecret = namespace("task.auth");
    noSecret.remove("task.auth.client.secret");
    OAuthAuthProvider.clearSharedSources();
    expectThrows(IllegalStateException.class,
        () -> AuthProviderUtils.extractAuthProvider(new PinotConfiguration(noSecret), "task.auth"));
  }

  @Test
  public void testGoogleServiceAccount()
      throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    String pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(
        keyPair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
    File keyFile = File.createTempFile("service-account", ".json");
    keyFile.deleteOnExit();
    // The key file as Google writes it: the PEM's line breaks escaped in the JSON string
    Files.writeString(keyFile.toPath(), "{\"type\":\"service_account\",\"client_email\":"
        + "\"pinot@proj.iam.gserviceaccount.com\",\"private_key_id\":\"k1\",\"private_key\":\""
        + pem.replace("\r", "").replace("\n", "\\n") + "\",\"token_uri\":\"" + _base + "/google/token\"}");
    Map<String, Object> config = new HashMap<>();
    config.put("task.auth.provider.class", OAuthAuthProvider.class.getName());
    config.put("task.auth.source", "google_service_account");
    config.put("task.auth.credentials.file", keyFile.getAbsolutePath());
    config.put("task.auth.target.audience", "pinot-client");
    AuthProvider provider = AuthProviderUtils.extractAuthProvider(new PinotConfiguration(config), "task.auth");
    assertTrue(provider.getTaskToken().startsWith("Bearer eyJhbGciOiJSUzI1NiJ9."));
    // The assertion is a JWT signed with the service account key, for the token endpoint, with the target audience
    String body = _requests.get(0)[1];
    assertTrue(body.startsWith("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="), body);
    SignedJWT assertion = SignedJWT.parse(body.substring(body.indexOf("assertion=") + "assertion=".length()));
    assertTrue(assertion.verify(new RSASSAVerifier((RSAPublicKey) keyPair.getPublic())));
    assertEquals(assertion.getJWTClaimsSet().getIssuer(), "pinot@proj.iam.gserviceaccount.com");
    assertEquals(assertion.getJWTClaimsSet().getAudience(), List.of(_base + "/google/token"));
    assertEquals(assertion.getJWTClaimsSet().getClaim("target_audience"), "pinot-client");
    assertEquals(assertion.getHeader().getKeyID(), "k1");
  }

  @Test
  public void testHttpTokenSource() {
    Map<String, Object> config = new HashMap<>();
    config.put("pinot.server.segment.uploader.auth.provider.class", OAuthAuthProvider.class.getName());
    config.put("pinot.server.segment.uploader.auth.source", "http");
    config.put("pinot.server.segment.uploader.auth.client.id", "pinot-service");
    config.put("pinot.server.segment.uploader.auth.api.key", "k3y");
    config.put("pinot.server.segment.uploader.auth.request.url", _base + "/custom/token");
    config.put("pinot.server.segment.uploader.auth.request.header.key", "X-Api-Key: ${secret:api.key}");
    config.put("pinot.server.segment.uploader.auth.request.body", "{\"clientId\":\"${client.id}\"}");
    config.put("pinot.server.segment.uploader.auth.map.token", "$.data.jwt");
    config.put("pinot.server.segment.uploader.auth.map.expiresIn", "$.data.ttl");
    AuthProvider provider = AuthProviderUtils.extractAuthProvider(new PinotConfiguration(config),
        "pinot.server.segment.uploader.auth");
    assertEquals(provider.getTaskToken(), "Bearer custom-1");
    assertEquals(_requests.get(0)[0], "k3y");
    assertEquals(_requests.get(0)[1], "{\"clientId\":\"pinot-service\"}");
  }
}
