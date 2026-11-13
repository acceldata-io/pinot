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
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.plugin.auth.oauth2.testhandlers.ScriptedHandler;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMetrics;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.metrics.PinotMetricUtils;
import org.apache.pinot.spi.metrics.PinotMetricsRegistry;
import org.apache.pinot.spi.plugin.PluginManager;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// Custom (`java`) handlers loaded from their own jar, the guard around every handler, issuer / pattern routing across
/// handler types, and the Google preset.
public class CustomHandlerTest {
  private static final SecretResolver SECRETS = alias -> {
    throw new IllegalArgumentException("no secrets in this test");
  };
  private File _handlersDir;

  /// Packs the testhandlers package into handlersDir/<name>/custom-handler.jar, as a deployment would.
  @BeforeClass
  public void buildHandlerJar()
      throws Exception {
    _handlersDir = Files.createTempDirectory("pinot-auth-handlers").toFile();
    URL classUrl = ScriptedHandler.class.getResource("ScriptedHandler.class");
    File packageDir = new File(classUrl.toURI()).getParentFile();
    for (String name : new String[]{"custom", "phonepe", "opaque", "other", "metered"}) {
      File dir = new File(_handlersDir, name);
      assertTrue(dir.mkdirs());
      try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(new File(dir, "custom-handler.jar")))) {
        for (File cls : packageDir.listFiles((d, n) -> n.endsWith(".class"))) {
          jar.putNextEntry(new JarEntry("org/apache/pinot/plugin/auth/oauth2/testhandlers/" + cls.getName()));
          jar.write(Files.readAllBytes(cls.toPath()));
          jar.closeEntry();
        }
      }
    }
  }

  @AfterClass
  public void cleanUp() {
    FileUtils.deleteQuietly(_handlersDir);
  }

  private OAuth2Authenticator authenticator(String handlers, Map<String, Object> props) {
    Map<String, Object> all = new HashMap<>(props);
    all.put("handlers", handlers);
    all.put("handlers.dir", _handlersDir.getAbsolutePath());
    OAuth2Authenticator authenticator = new OAuth2Authenticator();
    authenticator.init(new PinotConfiguration(all), SECRETS);
    return authenticator;
  }

  private static Map<String, Object> java(String name, String mode) {
    Map<String, Object> props = new HashMap<>();
    props.put("handler." + name + ".type", "java");
    props.put("handler." + name + ".class", ScriptedHandler.class.getName());
    props.put("handler." + name + ".mode", mode);
    return props;
  }

  private static PinotPrincipal auth(OAuth2Authenticator authenticator, String token) {
    return authenticator.authenticate(AuthCredential.parse("Bearer " + token));
  }

  @Test
  public void testJarHandlerIsIsolatedAndConfigured() {
    Map<String, Object> props = java("custom", "accept");
    props.put("handler.custom.custom.setting", "value-from-config");
    OAuth2Authenticator authenticator = authenticator("custom", props);
    PinotPrincipal principal = auth(authenticator, "ok-alice");
    assertEquals(principal.getUser(), "alice");
    assertEquals(principal.getClaims().get("loader"), HandlerClassLoader.class.getName());
    assertEquals(principal.getClaims().get("seesPinotInternals"), false);
    assertEquals(principal.getClaims().get("contextLoaderIsOwn"), true);
    assertEquals(principal.getClaims().get("setting"), "value-from-config");
    // The handler's own rejection and "not mine" both end in 401
    expectThrows(AuthenticationException.class, () -> auth(authenticator, "bad-token"));
    expectThrows(AuthenticationException.class, () -> auth(authenticator, "unknown-token"));
    authenticator.close();
  }

  @Test
  public void testFailingHandlersRejectAndNeverPass() {
    for (String mode : new String[]{"throw", "error", "null"}) {
      OAuth2Authenticator authenticator = authenticator("custom", java("custom", mode));
      AuthenticationException e = expectThrows(AuthenticationException.class, () -> auth(authenticator, "ok-alice"));
      assertTrue(e.getChallenge().startsWith("Bearer realm=\"pinot\""), mode);
      assertFalse(e.getMessage().contains("ok-alice"), mode);
      authenticator.close();
    }
    Map<String, Object> slow = java("custom", "slow");
    slow.put("handler.custom.timeout.ms", "200");
    OAuth2Authenticator authenticator = authenticator("custom", slow);
    long start = System.currentTimeMillis();
    AuthenticationException e = expectThrows(AuthenticationException.class, () -> auth(authenticator, "ok-alice"));
    assertTrue(e.getMessage().contains("timeout"), e.getMessage());
    assertTrue(System.currentTimeMillis() - start < 2000, "the timeout must not wait for the slow handler");
    authenticator.close();
  }

  @Test
  public void testResultsAreCachedPerToken() {
    // Loaded from the test classpath so the call counter is the same class as here (a jar copy has its own statics)
    Map<String, Object> cached = java("custom", "accept");
    cached.put("handler.custom.allow.classpath", "true");
    OAuth2Authenticator authenticator = authenticator("custom", cached);
    int before = ScriptedHandler.CALLS.get();
    auth(authenticator, "ok-carol");
    auth(authenticator, "ok-carol");
    assertEquals(ScriptedHandler.CALLS.get(), before + 1);
    auth(authenticator, "ok-dave");
    assertEquals(ScriptedHandler.CALLS.get(), before + 2);
    authenticator.close();
    Map<String, Object> noCache = java("custom", "accept");
    noCache.put("handler.custom.allow.classpath", "true");
    noCache.put("handler.custom.cache.ttl.seconds", "0");
    OAuth2Authenticator uncached = authenticator("custom", noCache);
    int calls = ScriptedHandler.CALLS.get();
    auth(uncached, "ok-carol");
    auth(uncached, "ok-carol");
    assertEquals(ScriptedHandler.CALLS.get(), calls + 2);
    uncached.close();
  }

  /// A custom provider whose JWTs are routed by issuer, next to a pattern-routed opaque handler.
  @Test
  public void testRoutingAcrossHandlerTypes()
      throws Exception {
    Map<String, Object> props = java("phonepe", "jwt-tid");
    props.put("handler.phonepe.issuer", "identityManager");
    props.putAll(java("opaque", "accept"));
    props.put("handler.opaque.token.pattern", "ok-.*");
    OAuth2Authenticator authenticator = authenticator("phonepe,opaque", props);

    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS512).type(JOSEObjectType.JWT).build(),
        new JWTClaimsSet.Builder().issuer("identityManager").claim("version", "4.0")
            .claim("tid", "8dc66d04-8299-4362-8848-adf3b3ca1d13").claim("sid", "s-1")
            .expirationTime(new Date(System.currentTimeMillis() + 600_000)).build());
    jwt.sign(new MACSigner("a-secret-only-the-provider-knows-0123456789-0123456789-0123456789"
        .getBytes(StandardCharsets.UTF_8)));
    assertEquals(auth(authenticator, jwt.serialize()).getUser(), "8dc66d04-8299-4362-8848-adf3b3ca1d13");
    assertEquals(auth(authenticator, "ok-erin").getUser(), "erin");
    // An opaque token outside every pattern, and a JWT of an unclaimed issuer, are rejected
    expectThrows(AuthenticationException.class, () -> auth(authenticator, "zz-erin"));
    SignedJWT foreign = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS512).build(),
        new JWTClaimsSet.Builder().issuer("someoneElse").claim("tid", "x").build());
    foreign.sign(new MACSigner("a-secret-only-the-provider-knows-0123456789-0123456789-0123456789"
        .getBytes(StandardCharsets.UTF_8)));
    AuthenticationException e = expectThrows(AuthenticationException.class, () -> auth(authenticator,
        foreign.serialize()));
    assertTrue(e.getMessage().contains("issuer is not configured"), e.getMessage());
    authenticator.close();

    Map<String, Object> clash = java("phonepe", "accept");
    clash.put("handler.phonepe.issuer", "identityManager");
    clash.putAll(java("other", "accept"));
    clash.put("handler.other.issuer", "identityManager");
    assertThrows(IllegalArgumentException.class, () -> authenticator("phonepe,other", clash));
  }

  @Test
  public void testMisconfiguredCustomHandlers() {
    Map<String, Object> noClass = java("custom", "accept");
    noClass.remove("handler.custom.class");
    assertThrows(IllegalArgumentException.class, () -> authenticator("custom", noClass));
    Map<String, Object> noJar = java("nojar", "accept");
    assertThrows(IllegalArgumentException.class, () -> authenticator("nojar", noJar));
    Map<String, Object> wrongClass = java("custom", "accept");
    wrongClass.put("handler.custom.class", "org.apache.pinot.plugin.auth.oauth2.testhandlers.Missing");
    assertThrows(IllegalStateException.class, () -> authenticator("custom", wrongClass));
    // A handler shipped with Pinot can opt into Pinot's classpath explicitly
    Map<String, Object> classpath = java("bundled", "accept");
    classpath.put("handler.bundled.allow.classpath", "true");
    OAuth2Authenticator authenticator = authenticator("bundled", classpath);
    assertEquals(auth(authenticator, "ok-frank").getClaims().get("seesPinotInternals"), true);
    authenticator.close();
  }

  @Test
  public void testGooglePreset()
      throws Exception {
    PinotConfiguration jwt = GoogleHandlerPreset.toJwtConfig(new PinotConfiguration(Map.of(
        "client.ids", "123-abc.apps.googleusercontent.com", "hosted.domain", "example.com")));
    assertEquals(jwt.getProperty("issuer"), "https://accounts.google.com");
    assertEquals(jwt.getProperty("jwks.url"), "https://www.googleapis.com/oauth2/v3/certs");
    assertEquals(jwt.getProperty("audiences"), "123-abc.apps.googleusercontent.com");
    assertEquals(jwt.getProperty("required.claims"), "email_verified=true,hd=example.com");
    assertEquals(jwt.getProperty("accept.id.tokens"), "true");
    assertEquals(jwt.getProperty("user.claim"), "email");
    assertThrows(IllegalArgumentException.class, () -> GoogleHandlerPreset.toJwtConfig(new PinotConfiguration()));
    try {
      new URL(GoogleHandlerPreset.JWKS_URL).openStream().close();
    } catch (Exception e) {
      throw new SkipException("Google not reachable: " + e.getMessage());
    }
    OAuth2Authenticator authenticator = authenticator("google", Map.of("handler.google.type", "google",
        "handler.google.client.ids", "123-abc.apps.googleusercontent.com"));
    // A token naming Google as issuer reaches the Google handler (and fails its signature check)
    SignedJWT fake = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
        new JWTClaimsSet.Builder().issuer("https://accounts.google.com").audience("123-abc.apps.googleusercontent.com")
            .claim("email", "a@example.com").expirationTime(new Date(System.currentTimeMillis() + 60_000)).build());
    fake.sign(new MACSigner("not-google-0123456789-0123456789-0123456789".getBytes(StandardCharsets.UTF_8)));
    AuthenticationException e = expectThrows(AuthenticationException.class, () -> auth(authenticator,
        fake.serialize()));
    assertTrue(e.getMessage().contains("google"), e.getMessage());
    authenticator.close();
    Path unused = _handlersDir.toPath();
    assertTrue(Files.isDirectory(unused));
  }

  @Test
  public void testIdentityMappingAppliesToEveryHandler() {
    Map<String, Object> props = java("custom", "accept");
    props.put("handler.custom.user.rules", "^(.*)$/$1@corp/U");
    props.put("handler.custom.service.users", "ALICE@CORP");
    OAuth2Authenticator authenticator = authenticator("custom", props);
    PinotPrincipal principal = auth(authenticator, "ok-alice");
    assertEquals(principal.getUser(), "ALICE@CORP");
    assertTrue(principal.isServiceAccount());
    assertEquals(principal.getClaims().get("token_user"), "alice");
    assertEquals(principal.getClaims().get("handler"), "custom");
    authenticator.close();
  }

  @Test
  public void testHandlerMetrics() {
    OAuth2Authenticator authenticator = authenticator("metered", java("metered", "accept"));
    auth(authenticator, "ok-alice");
    auth(authenticator, "ok-alice");
    expectThrows(AuthenticationException.class, () -> auth(authenticator, "bad-token"));
    authenticator.close();
    assertEquals(meter("oauth2.handler.metered.accepted"), 1);
    // java handlers are cached: the second call is a cache hit
    assertEquals(meter("oauth2.handler.metered.cacheHits"), 1);
    assertEquals(meter("oauth2.handler.metered.rejected"), 1);
  }

  private static long meter(String name) {
    PinotMetricsRegistry registry = PinotMetricUtils.getPinotMetricsRegistry();
    return registry.newMeter(PinotMetricUtils.makePinotMetricName(AuthMetrics.class, AuthMetrics.PREFIX + name),
        "events", TimeUnit.SECONDS).count();
  }

  @Test
  public void testDefaultHandlersDirIsOutsideThePluginsDirectory() {
    String previous = System.getProperty(PluginManager.PLUGINS_DIR_PROPERTY_NAME);
    try {
      System.setProperty(PluginManager.PLUGINS_DIR_PROPERTY_NAME, "/opt/pinot/plugins;/opt/extra/plugins");
      assertEquals(OAuth2Authenticator.defaultHandlersDir(), new File("/opt/pinot/auth-handlers"));
      System.clearProperty(PluginManager.PLUGINS_DIR_PROPERTY_NAME);
      assertEquals(OAuth2Authenticator.defaultHandlersDir(), new File("auth-handlers").getAbsoluteFile());
    } finally {
      if (previous != null) {
        System.setProperty(PluginManager.PLUGINS_DIR_PROPERTY_NAME, previous);
      } else {
        System.clearProperty(PluginManager.PLUGINS_DIR_PROPERTY_NAME);
      }
    }
  }
}
