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
package org.apache.pinot.core.auth.authn;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [BasicAuthenticator]: valid and invalid passwords, unknown users, malformed credentials, passwords by alias,
/// groups and service accounts.
public class BasicAuthenticatorTest {

  private static BasicAuthenticator authenticator() {
    Map<String, Object> settings = new HashMap<>();
    settings.put("principals", "admin,svc_pinot,alice");
    settings.put("principals.admin.password", "verysecret");
    settings.put("principals.svc_pinot.password.alias", "pinot.service.password");
    settings.put("principals.svc_pinot.service.account", "true");
    settings.put("principals.alice.password", "a:b");
    settings.put("principals.alice.groups", "analysts,ops");
    BasicAuthenticator authenticator = new BasicAuthenticator();
    authenticator.init(new PinotConfiguration(settings), alias -> {
      if (!alias.equals("pinot.service.password")) {
        throw new IllegalArgumentException(alias);
      }
      return "s3rvice".toCharArray();
    });
    return authenticator;
  }

  private static AuthCredential basic(String userAndPassword) {
    return AuthCredential.parse("Basic " + Base64.getEncoder().encodeToString(
        userAndPassword.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void testAuthentication() {
    BasicAuthenticator authenticator = authenticator();
    PinotPrincipal admin = authenticator.authenticate(basic("admin:verysecret"));
    assertEquals(admin.getUser(), "admin");
    assertEquals(admin.getMethod(), AuthMethod.BASIC);
    assertFalse(admin.isServiceAccount());
    assertTrue(authenticator.authenticate(basic("svc_pinot:s3rvice")).isServiceAccount());
    // Padding is normalized as BasicAuth does
    assertEquals(authenticator.authenticate(AuthCredential.parse("Basic YWRtaW46dmVyeXNlY3JldA=====")).getUser(),
        "admin");
    // A colon in the password
    assertEquals(authenticator.authenticate(basic("alice:a:b")).getGroups(), Set.of("analysts", "ops"));

    for (AuthCredential bad : new AuthCredential[]{basic("admin:wrong"), basic("nobody:verysecret"),
        basic("nocolon"), basic(":verysecret"), AuthCredential.parse("Basic !!notbase64!!")}) {
      AuthenticationException e = expectThrows(AuthenticationException.class, () -> authenticator.authenticate(bad));
      assertEquals(e.getChallenge(), "Basic realm=\"pinot\"");
      assertFalse(e.getMessage().contains("verysecret"));
    }
  }

  @Test
  public void testConfiguration() {
    expectThrows(IllegalArgumentException.class,
        () -> new BasicAuthenticator().init(new PinotConfiguration(), alias -> new char[0]));
    expectThrows(IllegalArgumentException.class, () -> new BasicAuthenticator().init(
        new PinotConfiguration(Map.of("principals", "admin")), alias -> new char[0]));
  }
}
