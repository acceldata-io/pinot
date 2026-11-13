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
package org.apache.pinot.controller.api.access;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.apache.pinot.common.exception.HttpErrorStatusException;
import org.apache.pinot.controller.ControllerConf;
import org.apache.pinot.controller.helix.ControllerTest;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;


/// A controller with existing BasicAuth principals moved to [PinotAuthAccessControlFactory] with the `basic` method
/// and the native authorizer, and no other change: the same users sign in with the same passwords and keep their
/// access, and a table-scoped user is refused cluster endpoints (the apache/pinot#14595 reproduction).
public class NativeAuthorizationBasicAuthMigrationTest extends ControllerTest {
  private static final String PRINCIPALS = "controller.admin.access.control.principals";

  @BeforeClass
  public void setUp()
      throws Exception {
    startZk();
    Map<String, Object> config = getDefaultControllerConfiguration();
    // The BasicAuth settings the cluster already has
    config.put(PRINCIPALS, "admin,user");
    config.put(PRINCIPALS + ".admin.password", "verysecret");
    config.put(PRINCIPALS + ".user.password", "secret");
    config.put(PRINCIPALS + ".user.tables", "orders");
    config.put(PRINCIPALS + ".user.permissions", "read");
    // The switch
    config.put(ControllerConf.ACCESS_CONTROL_FACTORY_CLASS, PinotAuthAccessControlFactory.class.getName());
    config.put("pinot.auth.method", "basic");
    startController(config);
  }

  @AfterClass
  public void tearDown() {
    stopController();
    stopZk();
  }

  private static Map<String, String> basic(String user, String password) {
    return Map.of("Authorization", "Basic " + Base64.getEncoder().encodeToString(
        (user + ":" + password).getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void testUsersKeepTheirAccess()
      throws IOException {
    // The admin principal (no permissions, no tables) keeps full access
    sendGetRequest(_controllerBaseApiUrl + "/tables", basic("admin", "verysecret"));
    sendGetRequest(_controllerBaseApiUrl + "/zk/ls?path=/", basic("admin", "verysecret"));
    // The table-scoped user reaches its table (the table does not exist, so the endpoint itself answers 404)
    assertStatus(404, () -> sendGetRequest(_controllerBaseApiUrl + "/tables/orders/schema", basic("user", "secret")));
    // ... but not another table, and not a change of its own table
    assertStatus(403, () -> sendGetRequest(_controllerBaseApiUrl + "/tables/payments/schema", basic("user", "secret")));
    assertStatus(403, () -> sendDeleteRequest(_controllerBaseApiUrl + "/tables/orders", basic("user", "secret")));
  }

  @Test
  public void testClusterEndpointsNeedUnrestrictedScope() {
    // apache/pinot#14595: a table-scoped principal must not list the cluster's tables
    assertStatus(403, () -> sendGetRequest(_controllerBaseApiUrl + "/tables", basic("user", "secret")));
    assertStatus(403, () -> sendGetRequest(_controllerBaseApiUrl + "/zk/ls?path=/", basic("user", "secret")));
  }

  @Test
  public void testAuthentication() {
    assertStatus(401, () -> sendGetRequest(_controllerBaseApiUrl + "/tables"));
    assertStatus(401, () -> sendGetRequest(_controllerBaseApiUrl + "/tables", basic("admin", "wrong")));
    assertStatus(401, () -> sendGetRequest(_controllerBaseApiUrl + "/tables",
        Map.of("Authorization", "Bearer some-token")));
  }

  private static void assertStatus(int expectedStatus, IoRequest request) {
    try {
      request.send();
      fail("Expected HTTP status " + expectedStatus);
    } catch (IOException e) {
      assertTrue(e.getCause() instanceof HttpErrorStatusException, "Unexpected failure: " + e);
      assertEquals(((HttpErrorStatusException) e.getCause()).getStatusCode(), expectedStatus, e.getMessage());
    }
  }

  @FunctionalInterface
  private interface IoRequest {
    void send()
        throws IOException;
  }
}
