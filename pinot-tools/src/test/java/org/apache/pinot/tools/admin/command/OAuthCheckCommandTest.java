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
package org.apache.pinot.tools.admin.command;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;


/// [OAuthCheckCommand] against a pending configuration file, for each handler type (jwt, introspection, http, java):
/// accepted and rejected tokens, identity mapping, authorization preview, and no token or secret in the output.
public class OAuthCheckCommandTest {
  private static final String HMAC_SECRET = "an-hmac-secret-of-at-least-thirty-two-bytes!";
  private static final String CLIENT_SECRET = "introspection-client-secret";
  private static final String API_KEY = "http-handler-api-key";

  private HttpServer _server;
  private String _base;

  /// A custom handler: accepts tokens `ok-<user>`.
  public static class PrefixHandler implements OAuthTokenHandler {
    @Override
    public void init(HandlerContext context) {
    }

    @Override
    public TokenIdentity validate(String token) {
      if (!token.startsWith("ok-")) {
        throw new AuthenticationException("Invalid token (custom): unknown", "Bearer realm=\"pinot\"");
      }
      return new TokenIdentity(token.substring(3), Set.of("analysts"), Set.of(), Instant.now().plusSeconds(300),
          null, Map.of());
    }
  }

  @BeforeClass
  public void start()
      throws IOException {
    _server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    _server.setExecutor(Executors.newCachedThreadPool());
    _base = "http://127.0.0.1:" + _server.getAddress().getPort();
    _server.createContext("/introspect", exchange -> {
      String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      reply(exchange, body.contains("token=opaque-good") ? "{\"active\":true,\"username\":\"bob\",\"exp\":"
          + (Instant.now().getEpochSecond() + 300) + "}" : "{\"active\":false}");
    });
    _server.createContext("/validate", exchange -> {
      boolean ok = API_KEY.equals(exchange.getRequestHeaders().getFirst("X-Api-Key"))
          && "Bearer http-good".equals(exchange.getRequestHeaders().getFirst("Authorization"));
      reply(exchange, ok ? "{\"valid\":true,\"data\":{\"userId\":\"carol\"}}" : "{\"valid\":false}");
    });
    _server.start();
  }

  @AfterClass
  public void stop() {
    _server.stop(0);
  }

  private static void reply(HttpExchange exchange, String body)
      throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private File configFile()
      throws IOException {
    File file = File.createTempFile("pending-auth", ".properties");
    file.deleteOnExit();
    String config = String.join("\n",
        "pinot.auth.method=oauth2",
        "pinot.auth.oauth2.handlers=corp,introspect,idm,custom",
        "pinot.auth.oauth2.handler.corp.type=jwt",
        "pinot.auth.oauth2.handler.corp.issuer=https://idp.example.com",
        "pinot.auth.oauth2.handler.corp.algorithms=HS256",
        "pinot.auth.oauth2.handler.corp.hmac.secret.alias=corp.hmac",
        "pinot.auth.oauth2.handler.corp.audiences=pinot",
        "pinot.auth.oauth2.handler.corp.user.claim=email",
        "pinot.auth.oauth2.handler.corp.user.rules=^([^@]+)@example\\\\.com$/$1/L",
        "pinot.auth.oauth2.handler.introspect.type=introspection",
        "pinot.auth.oauth2.handler.introspect.introspection.url=" + _base + "/introspect",
        "pinot.auth.oauth2.handler.introspect.client.id=pinot",
        "pinot.auth.oauth2.handler.introspect.client.secret.alias=introspect.client",
        "pinot.auth.oauth2.handler.introspect.token.pattern=opaque-.*",
        "pinot.auth.oauth2.handler.idm.type=http",
        "pinot.auth.oauth2.handler.idm.request.url=" + _base + "/validate",
        "pinot.auth.oauth2.handler.idm.request.header.auth=Authorization: Bearer ${token}",
        "pinot.auth.oauth2.handler.idm.request.header.key=X-Api-Key: ${secret:idm.api.key}",
        "pinot.auth.oauth2.handler.idm.success.condition=$.valid == true",
        "pinot.auth.oauth2.handler.idm.map.user=$.data.userId",
        "pinot.auth.oauth2.handler.idm.token.pattern=http-.*",
        "pinot.auth.oauth2.handler.custom.type=java",
        "pinot.auth.oauth2.handler.custom.class=" + PrefixHandler.class.getName(),
        "pinot.auth.oauth2.handler.custom.allow.classpath=true",
        "pinot.auth.oauth2.handler.custom.token.pattern=ok-.*",
        "pinot.auth.secrets.corp.hmac=" + HMAC_SECRET,
        "pinot.auth.secrets.introspect.client=" + CLIENT_SECRET,
        "pinot.auth.secrets.idm.api.key=" + API_KEY,
        "pinot.authz.native.rules=analysts",
        "pinot.authz.native.rule.analysts.users=alice,bob,carol",
        "pinot.authz.native.rule.analysts.groups=analysts",
        "pinot.authz.native.rule.analysts.permissions=READ",
        "pinot.authz.native.rule.analysts.tables=orders");
    Files.writeString(file.toPath(), config);
    return file;
  }

  private static String jwt(String secret, String email)
      throws Exception {
    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
        .issuer("https://idp.example.com").audience("pinot").subject("u-1").claim("email", email)
        .expirationTime(Date.from(Instant.now().plusSeconds(300))).build());
    jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
    return jwt.serialize();
  }

  private String run(String token, boolean expectAccepted)
      throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    boolean accepted = new OAuthCheckCommand().setConfigFile(configFile().getAbsolutePath()).setToken(token)
        .setTables("orders,payments").setOutput(new PrintStream(bytes, true, StandardCharsets.UTF_8)).execute();
    String output = bytes.toString(StandardCharsets.UTF_8);
    assertTrue(accepted == expectAccepted, output);
    for (String secret : List.of(token, HMAC_SECRET, CLIENT_SECRET, API_KEY)) {
      assertFalse(output.contains(secret), "Output must not contain a token or secret:\n" + output);
    }
    return output;
  }

  @Test
  public void testEveryHandlerType()
      throws Exception {
    String jwtOutput = run(jwt(HMAC_SECRET, "Alice@example.com"), true);
    assertTrue(jwtOutput.contains("user: alice"), jwtOutput);
    assertTrue(jwtOutput.contains("token_user = Alice@example.com"), jwtOutput);
    assertTrue(jwtOutput.contains("Query on default.orders: allowed"), jwtOutput);
    assertTrue(jwtOutput.contains("Query on default.payments: denied"), jwtOutput);
    assertTrue(jwtOutput.contains("READ on cluster: denied"), jwtOutput);
    assertTrue(jwtOutput.contains("handler.corp.hmac.secret.alias = corp.hmac"), jwtOutput);

    assertTrue(run("opaque-good", true).contains("user: bob"));
    String httpOutput = run("http-good", true);
    assertTrue(httpOutput.contains("user: carol"), httpOutput);
    assertTrue(httpOutput.contains("handler.idm.request.header.key = ****"), httpOutput);
    assertTrue(run("ok-dave", true).contains("groups: [analysts]"));
  }

  @Test
  public void testRejectedTokens()
      throws Exception {
    assertTrue(run(jwt("another-secret-of-at-least-thirty-two-bytes", "alice@example.com"), false)
        .contains("Result: REJECTED"));
    assertTrue(run("opaque-bad", false).contains("REJECTED"));
    assertTrue(run("http-bad", false).contains("REJECTED"));
    assertTrue(run("unknown-format", false).contains("REJECTED"));
  }
}
