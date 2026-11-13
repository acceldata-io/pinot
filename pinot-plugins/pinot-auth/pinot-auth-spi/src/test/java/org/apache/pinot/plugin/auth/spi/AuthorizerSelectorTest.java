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
package org.apache.pinot.plugin.auth.spi;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// Mode selection, settings and the shared-settings merge of [AuthorizerSelector], and [ConfigSecretResolver].
public class AuthorizerSelectorTest {

  /// A native-mode authorizer that records its settings.
  public static class RecordingNativeAuthorizer implements PinotAuthorizer {
    PinotConfiguration _config;

    @Override
    public AuthorizationMode getMode() {
      return AuthorizationMode.NATIVE;
    }

    @Override
    public void init(PinotConfiguration config) {
      _config = config;
    }

    @Override
    public AuthorizationDecision authorize(PinotPrincipal principal, AccessRequest request) {
      return AuthorizationDecision.deny("test");
    }
  }

  private static PinotConfiguration config(String... keyValues) {
    Map<String, Object> map = new HashMap<>();
    for (int i = 0; i < keyValues.length; i += 2) {
      map.put(keyValues[i], keyValues[i + 1]);
    }
    return new PinotConfiguration(map);
  }

  @Test
  public void testModeSelection() {
    assertEquals(AuthorizerSelector.getConfiguredMode(config()), AuthorizationMode.NATIVE);
    assertEquals(AuthorizerSelector.getConfiguredMode(config("pinot.authz.mode", " Ranger ")),
        AuthorizationMode.RANGER);
    expectThrows(IllegalArgumentException.class,
        () -> AuthorizerSelector.getConfiguredMode(config("pinot.authz.mode", "acl")));
    assertEquals(AuthorizerSelector.getAuthorizerClass(config(), AuthorizationMode.NATIVE),
        AuthorizerSelector.DEFAULT_NATIVE_AUTHORIZER);
    assertEquals(AuthorizerSelector.getAuthorizerClass(config(), AuthorizationMode.RANGER),
        AuthorizerSelector.DEFAULT_RANGER_AUTHORIZER);
  }

  @Test
  public void testCreateOnlyTheConfiguredMode() {
    PinotAuthorizer authorizer = AuthorizerSelector.create(config(
        "pinot.authz.native.authorizer.class", RecordingNativeAuthorizer.class.getName(),
        "pinot.authz.native.rules", "analysts",
        "pinot.authz.ranger.service.name", "not-for-native"));
    assertTrue(authorizer instanceof RecordingNativeAuthorizer);
    PinotConfiguration settings = ((RecordingNativeAuthorizer) authorizer)._config;
    assertEquals(settings.getProperty("rules"), "analysts");
    assertEquals(settings.getProperty("service.name"), null);

    // Ranger mode without the plug-in fails the start; it never falls back to native
    IllegalStateException missing = expectThrows(IllegalStateException.class,
        () -> AuthorizerSelector.create(config("pinot.authz.mode", "ranger")));
    assertTrue(missing.getMessage().contains("Install the Ranger Pinot plug-in"), missing.getMessage());

    // A class of another mode is refused
    IllegalStateException mismatch = expectThrows(IllegalStateException.class, () -> AuthorizerSelector.create(
        config("pinot.authz.mode", "ranger", "pinot.authz.ranger.authorizer.class",
            RecordingNativeAuthorizer.class.getName())));
    assertTrue(mismatch.getMessage().contains("implements mode native"), mismatch.getMessage());
  }

  @Test
  public void testEnforceAndServiceAccounts() {
    assertTrue(AuthorizerSelector.isEnforced(config()));
    assertFalse(AuthorizerSelector.isEnforced(config("pinot.authz.enforce", "false")));
    assertEquals(AuthorizerSelector.getServiceAccounts(config("pinot.authz.service.accounts", "pinot, svc-ingest,")),
        Set.of("pinot", "svc-ingest"));
    assertTrue(AuthorizerSelector.getServiceAccounts(config()).isEmpty());
  }

  @Test
  public void testClusterSettingsReachTheFactorySubset() {
    PinotConfiguration component = config(
        "pinot.broker.access.control.class", "SomeFactory",
        "pinot.broker.access.control.principals", "admin",
        "pinot.auth.method", "oauth2",
        "pinot.auth.oauth2.handlers", "idm,google",
        "pinot.authz.mode", "native",
        "pinot.broker.timeout.ms", "1000");
    PinotConfiguration merged = AuthorizerSelector.withClusterAuthSettings(
        component.subset("pinot.broker.access.control"), component);
    assertEquals(merged.getProperty("class"), "SomeFactory");
    assertEquals(merged.getProperty("principals"), "admin");
    assertEquals(merged.getProperty("pinot.auth.method"), "oauth2");
    assertEquals(merged.getProperty("pinot.auth.oauth2.handlers"), "idm,google");
    assertEquals(merged.getProperty("pinot.authz.mode"), "native");
    assertEquals(merged.getProperty("pinot.broker.timeout.ms"), null);
  }

  @Test
  public void testConfigSecretResolver() {
    ConfigSecretResolver resolver = new ConfigSecretResolver(config("pinot.auth.secrets.idm.client.secret", "s3cret"));
    assertEquals(new String(resolver.resolve("idm.client.secret")), "s3cret");
    IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> resolver.resolve("other"));
    assertTrue(e.getMessage().contains("pinot.auth.secrets.other"));
  }

  @Test
  public void testPermissionsAndRequests() {
    assertTrue(Permission.ALL.grants(Permission.ADMIN));
    assertTrue(Permission.READ.grants(Permission.READ));
    assertFalse(Permission.UPDATE.grants(Permission.READ));
    assertEquals(Permission.fromName(" admin "), Permission.ADMIN);
    expectThrows(IllegalArgumentException.class, () -> Permission.fromName("WRITE"));
    expectThrows(IllegalArgumentException.class,
        () -> new AccessRequest(ResourceType.TABLE, "default", null, null, Permission.READ, "query"));
    expectThrows(IllegalArgumentException.class,
        () -> new AccessRequest(ResourceType.CLUSTER, null, null, null, Permission.ALL, "all"));
    assertEquals(new AccessRequest(ResourceType.TABLE, "fin", "payments", "Query", Permission.READ, "query")
        .toString(), "Query on fin.payments");
  }
}
