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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.pinot.plugin.auth.oauth2.OAuth2Authenticator;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// Packs the sample classes into a jar under `<handlers.dir>/<name>/`, as a deployment does, and loads them through
/// the router's `java` handler type next to a built-in handler. Proves the samples need nothing beyond what the
/// isolated handler class loader exposes (JDK, authentication SPI, configuration type, SLF4J): that loader never
/// delegates the sample package to the test class path, so the handler can only have come from the packed jar.
public class SampleJarLoadingTest {
  private File _handlersDir;
  private MockIdpServer _idp;

  @BeforeClass
  public void setUp()
      throws Exception {
    _idp = new MockIdpServer();
    _handlersDir = Files.createTempDirectory("pinot-auth-handlers").toFile();
    File dir = new File(_handlersDir, "idm");
    assertTrue(dir.mkdirs());
    Path classes = Paths.get(CustomIdpTokenHandler.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    List<Path> files;
    try (Stream<Path> walk = Files.walk(classes)) {
      files = walk.filter(Files::isRegularFile).collect(Collectors.toList());
    }
    try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(new File(dir, "pinot-auth-samples.jar")))) {
      for (Path file : files) {
        jar.putNextEntry(new JarEntry(classes.relativize(file).toString().replace(File.separatorChar, '/')));
        jar.write(Files.readAllBytes(file));
        jar.closeEntry();
      }
    }
  }

  @AfterClass
  public void tearDown()
      throws IOException {
    _idp.close();
    try (Stream<Path> walk = Files.walk(_handlersDir.toPath())) {
      for (Path path : walk.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
        Files.delete(path);
      }
    }
  }

  @Test
  public void testSampleHandlerLoadsFromItsJar() {
    _idp.answer("/v1/userinfo", 200, "{\"data\":{\"userId\":\"alice\",\"roles\":[\"analysts\"]}}");
    Map<String, Object> props = new HashMap<>();
    props.put("handlers", "idm");
    props.put("handlers.dir", _handlersDir.getAbsolutePath());
    props.put("handler.idm.type", "java");
    props.put("handler.idm.class", CustomIdpTokenHandler.class.getName());
    props.put("handler.idm.issuer", CustomIdpTokenHandlerTest.ISSUER);
    props.put("handler.idm.hmac.secret.alias", "idm.secret");
    props.put("handler.idm.required.claims", "tid,sid");
    props.put("handler.idm.userinfo.url", _idp.url("/v1/userinfo"));
    props.put("handler.idm.user.field", "data.userId");
    props.put("handler.idm.groups.field", "data.roles");
    OAuth2Authenticator authenticator = new OAuth2Authenticator();
    authenticator.init(new PinotConfiguration(props), alias -> {
      if (!alias.equals("idm.secret")) {
        throw new IllegalArgumentException("Unknown alias " + alias);
      }
      return CustomIdpTokenHandlerTest.SECRET.toCharArray();
    });
    try {
      long now = System.currentTimeMillis() / 1000;
      String token = CustomIdpTokenHandlerTest.token("HS512", CustomIdpTokenHandlerTest.SECRET,
          CustomIdpTokenHandlerTest.claims(CustomIdpTokenHandlerTest.ISSUER, now - 10, now + 600));
      PinotPrincipal principal = authenticator.authenticate(AuthCredential.parse("Bearer " + token));
      assertEquals(principal.getUser(), "alice");
      assertTrue(principal.getGroups().contains("analysts"), principal.getGroups().toString());
      assertEquals(principal.getClaims().get("handler"), "idm");

      String forged = CustomIdpTokenHandlerTest.token("HS512", "not-the-secret",
          CustomIdpTokenHandlerTest.claims(CustomIdpTokenHandlerTest.ISSUER, now - 10, now + 600));
      expectThrows(AuthenticationException.class,
          () -> authenticator.authenticate(AuthCredential.parse("Bearer " + forged)));
    } finally {
      authenticator.close();
    }
  }
}
