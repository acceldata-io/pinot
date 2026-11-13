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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;


/// A minimal OpenID Connect provider for tests: serves the discovery document and the public key set, counts key set
/// fetches, can rotate keys, and signs tokens.
final class TestIdentityProvider implements AutoCloseable {
  final HttpServer _server;
  final String _issuer;
  final AtomicInteger _jwksFetches = new AtomicInteger();
  volatile String _discoveryIssuer;
  final List<JWK> _published = new ArrayList<>();
  RSAKey _rsa;

  TestIdentityProvider()
      throws Exception {
    _server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    _issuer = "http://localhost:" + _server.getAddress().getPort() + "/realms/test";
    _discoveryIssuer = _issuer;
    _rsa = new RSAKeyGenerator(2048).keyID("k1").generate();
    _published.add(_rsa.toPublicJWK());
    _server.createContext("/realms/test/.well-known/openid-configuration", exchange -> respond(exchange,
        "{\"issuer\":\"" + _discoveryIssuer + "\",\"jwks_uri\":\"" + _issuer + "/certs\"}"));
    _server.createContext("/realms/test/certs", exchange -> {
      _jwksFetches.incrementAndGet();
      List<JWK> keys;
      synchronized (_published) {
        keys = new ArrayList<>(_published);
      }
      respond(exchange, new JWKSet(keys).toString());
    });
    _server.start();
  }

  private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body)
      throws java.io.IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  String jwksUrl() {
    return _issuer + "/certs";
  }

  /// Replaces the signing key and publishes only the new one.
  void rotate(String kid)
      throws Exception {
    _rsa = new RSAKeyGenerator(2048).keyID(kid).generate();
    synchronized (_published) {
      _published.clear();
      _published.add(_rsa.toPublicJWK());
    }
  }

  JWTClaimsSet.Builder claims(String audience) {
    long now = System.currentTimeMillis();
    return new JWTClaimsSet.Builder().issuer(_issuer).subject("alice").audience(audience)
        .expirationTime(new Date(now + 300_000)).issueTime(new Date(now)).claim("groups", List.of("analysts", "ops"));
  }

  String sign(JWTClaimsSet claims)
      throws Exception {
    return sign(claims, JOSEObjectType.JWT);
  }

  String sign(JWTClaimsSet claims, JOSEObjectType type)
      throws Exception {
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(_rsa.getKeyID()).type(type).build(),
        claims);
    jwt.sign(new RSASSASigner(_rsa));
    return jwt.serialize();
  }

  /// Signed with a key this provider never published (same kid).
  String signWithForeignKey(JWTClaimsSet claims)
      throws Exception {
    RSAKey foreign = new RSAKeyGenerator(2048).keyID(_rsa.getKeyID()).generate();
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(foreign.getKeyID()).build(), claims);
    jwt.sign(new RSASSASigner(foreign));
    return jwt.serialize();
  }

  String signEs256(JWTClaimsSet claims)
      throws Exception {
    ECKey ec = new ECKeyGenerator(Curve.P_256).keyID("ec1").generate();
    synchronized (_published) {
      _published.add(ec.toPublicJWK());
    }
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("ec1").build(), claims);
    jwt.sign(new ECDSASigner(ec));
    return jwt.serialize();
  }

  /// Algorithm confusion: HS256 with the provider's public key bytes as the HMAC secret.
  String signHs256WithPublicKey(JWTClaimsSet claims)
      throws Exception {
    byte[] secret = _rsa.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8);
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(_rsa.getKeyID()).build(), claims);
    jwt.sign(new MACSigner(secret));
    return jwt.serialize();
  }

  static String signHs256(JWTClaimsSet claims, String secret)
      throws Exception {
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), claims);
    jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
    return jwt.serialize();
  }

  static String unsigned(JWTClaimsSet claims) {
    return new PlainJWT(claims).serialize();
  }

  @Override
  public void close() {
    _server.stop(0);
  }
}
