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
package org.apache.pinot.perf;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.pinot.core.auth.authz.NativeAuthorizer;
import org.apache.pinot.plugin.auth.oauth2.OAuth2Authenticator;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.ResourceType;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.OptionsBuilder;


/// Cost of the `oauth2` authentication method per request, as the broker and controller pay it:
/// - `jwt`: an RS256 JWT verified with the issuer's cached key set (signature, issuer, audience, expiry, claims) and
///   mapped to the Pinot principal. Every token is distinct, so nothing is served from a result cache.
/// - `jwtAndNativeAuthorization`: the same, plus the native authorizer's table decision and row filters.
/// - `introspection` / `http`: opaque tokens checked by an RFC 7662 introspection endpoint / a provider validation
///   API on localhost, with the handler result cache at `hitRatio` percent hits; a miss pays the HTTP round trip.
///
/// The identity provider is an in-process HTTP server, so a miss measures Pinot's side plus a loopback call, not a
/// real provider's latency. Run with `-Dauth.threads=N` to measure under contention (default 1 thread).
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class BenchmarkOAuth2Authentication {
  private static final String AUDIENCE = "pinot";
  private static final int TOKENS = 4096;
  private static final int HOT_TOKENS = 1024;

  @Param({"90", "99"})
  public int _hitRatio;

  private HttpServer _server;
  private OAuth2Authenticator _jwt;
  private OAuth2Authenticator _introspection;
  private OAuth2Authenticator _http;
  private NativeAuthorizer _authorizer;
  private AuthCredential[] _jwtTokens;
  private AuthCredential[] _hotOpaqueTokens;
  private AccessRequest _queryOrders;

  /// Per-thread position in the token lists and miss counter.
  @State(Scope.Thread)
  public static class Cursor {
    int _next;
    long _misses;

    int next(int bound) {
      int i = _next;
      _next = i + 1 == bound ? 0 : i + 1;
      return i;
    }
  }

  @Setup(Level.Trial)
  public void setUp()
      throws Exception {
    RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
    String keySet = new JWKSet(key.toPublicJWK()).toString();
    _server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    _server.setExecutor(Executors.newFixedThreadPool(8));
    String base = "http://127.0.0.1:" + _server.getAddress().getPort();
    String issuer = base + "/realms/bench";
    long exp = System.currentTimeMillis() / 1000 + 7200;
    _server.createContext("/realms/bench/certs", exchange -> reply(exchange, keySet));
    // Any presented token is active / valid: the benchmark measures the cost, not the decision
    _server.createContext("/introspect", exchange -> {
      exchange.getRequestBody().readAllBytes();
      reply(exchange, "{\"active\":true,\"username\":\"alice\",\"groups\":[\"analysts\"],\"aud\":\"" + AUDIENCE
          + "\",\"exp\":" + exp + "}");
    });
    _server.createContext("/validate", exchange -> reply(exchange,
        "{\"valid\":true,\"expiresAt\":" + exp + ",\"data\":{\"userId\":\"alice\",\"groups\":[\"analysts\"]}}"));
    _server.start();

    Map<String, Object> jwt = new HashMap<>();
    jwt.put("handlers", "bench");
    jwt.put("handler.bench.type", "jwt");
    jwt.put("handler.bench.issuer", issuer);
    jwt.put("handler.bench.audiences", AUDIENCE);
    jwt.put("handler.bench.jwks.url", issuer + "/certs");
    _jwt = authenticator(jwt);

    Map<String, Object> introspection = new HashMap<>();
    introspection.put("handlers", "bench");
    introspection.put("handler.bench.type", "introspection");
    introspection.put("handler.bench.introspection.url", base + "/introspect");
    introspection.put("handler.bench.client.id", "pinot");
    introspection.put("handler.bench.client.secret.alias", "bench.secret");
    introspection.put("handler.bench.audiences", AUDIENCE);
    introspection.put("handler.bench.cache.ttl.seconds", "3600");
    _introspection = authenticator(introspection);

    Map<String, Object> http = new HashMap<>();
    http.put("handlers", "bench");
    http.put("handler.bench.type", "http");
    http.put("handler.bench.client.id", "pinot");
    http.put("handler.bench.request.url", base + "/validate");
    http.put("handler.bench.request.method", "GET");
    http.put("handler.bench.request.header.auth", "Authorization: Bearer ${token}");
    http.put("handler.bench.success.condition", "$.valid == true");
    http.put("handler.bench.map.user", "$.data.userId");
    http.put("handler.bench.map.groups", "$.data.groups");
    http.put("handler.bench.map.expiresAt", "$.expiresAt");
    http.put("handler.bench.map.expiresAt.format", "epochSeconds");
    http.put("handler.bench.cache.ttl.seconds", "3600");
    _http = authenticator(http);

    Map<String, Object> rules = new HashMap<>();
    rules.put("rules", "analysts,admins");
    rules.put("rule.analysts.groups", "analysts");
    rules.put("rule.analysts.permissions", "READ");
    rules.put("rule.analysts.tables", "orders,orders_*");
    rules.put("rule.analysts.rowFilter.orders", "region = 'south'");
    rules.put("rule.admins.groups", "pinot-admins");
    rules.put("rule.admins.permissions", "ALL");
    rules.put("rule.admins.tables", "*");
    _authorizer = new NativeAuthorizer();
    _authorizer.init(new PinotConfiguration(rules));
    _queryOrders = new AccessRequest(ResourceType.TABLE, "default", "orders", null, Permission.READ, "query");

    RSASSASigner signer = new RSASSASigner(key);
    _jwtTokens = new AuthCredential[TOKENS];
    for (int i = 0; i < TOKENS; i++) {
      SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(),
          new JWTClaimsSet.Builder().issuer(issuer).audience(AUDIENCE).subject("alice").claim("groups",
              List.of("analysts")).jwtID("jti-" + i).issueTime(new Date()).expirationTime(new Date(exp * 1000))
              .build());
      token.sign(signer);
      _jwtTokens[i] = AuthCredential.parse("Bearer " + token.serialize());
    }
    // Opaque tokens: the hot set is validated once here, so measured hits are cache hits
    _hotOpaqueTokens = new AuthCredential[HOT_TOKENS];
    for (int i = 0; i < HOT_TOKENS; i++) {
      _hotOpaqueTokens[i] = AuthCredential.parse("Bearer hot-" + i);
      _introspection.authenticate(_hotOpaqueTokens[i]);
      _http.authenticate(_hotOpaqueTokens[i]);
    }
    // Every JWT once, so the key set is loaded and the JIT has seen the path before measurement
    for (AuthCredential token : _jwtTokens) {
      check(_jwt.authenticate(token));
    }
  }

  private static OAuth2Authenticator authenticator(Map<String, Object> settings) {
    OAuth2Authenticator authenticator = new OAuth2Authenticator();
    authenticator.init(new PinotConfiguration(settings), alias -> {
      if ("bench.secret".equals(alias)) {
        return "bench-client-secret".toCharArray();
      }
      throw new IllegalArgumentException("unknown alias " + alias);
    });
    return authenticator;
  }

  private static void reply(HttpExchange exchange, String body)
      throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private static PinotPrincipal check(PinotPrincipal principal) {
    if (!"alice".equals(principal.getUser())) {
      throw new IllegalStateException("unexpected principal " + principal.getUser());
    }
    return principal;
  }

  @TearDown(Level.Trial)
  public void tearDown() {
    _jwt.close();
    _introspection.close();
    _http.close();
    _server.stop(0);
  }

  @Benchmark
  public PinotPrincipal jwt(Cursor cursor) {
    return _jwt.authenticate(_jwtTokens[cursor.next(TOKENS)]);
  }

  @Benchmark
  public List<String> jwtAndNativeAuthorization(Cursor cursor) {
    PinotPrincipal principal = _jwt.authenticate(_jwtTokens[cursor.next(TOKENS)]);
    AuthorizationDecision decision = _authorizer.authorize(principal, _queryOrders);
    if (!decision.isAllowed()) {
      throw new IllegalStateException("denied: " + decision);
    }
    return _authorizer.getRowFilters(principal, "default", "orders");
  }

  @Benchmark
  public PinotPrincipal introspection(Cursor cursor) {
    return _introspection.authenticate(pick(cursor));
  }

  @Benchmark
  public PinotPrincipal http(Cursor cursor) {
    return _http.authenticate(pick(cursor));
  }

  /// `_hitRatio` percent of the requests reuse a validated token; the others present a token never seen before.
  private AuthCredential pick(Cursor cursor) {
    int i = cursor.next(100 * HOT_TOKENS);
    if (i % 100 >= _hitRatio) {
      return AuthCredential.parse("Bearer miss-" + Thread.currentThread().getId() + "-" + cursor._misses++);
    }
    return _hotOpaqueTokens[i % HOT_TOKENS];
  }

  public static void main(String[] args)
      throws Exception {
    ChainedOptionsBuilder opt = new OptionsBuilder().include(BenchmarkOAuth2Authentication.class.getSimpleName())
        .threads(Integer.getInteger("auth.threads", 1));
    new Runner(opt.build()).run();
  }
}
