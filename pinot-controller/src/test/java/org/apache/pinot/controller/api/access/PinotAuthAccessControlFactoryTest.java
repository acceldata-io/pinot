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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.apache.pinot.common.exception.HttpErrorStatusException;
import org.apache.pinot.controller.ControllerConf;
import org.apache.pinot.controller.helix.ControllerTest;
import org.apache.pinot.core.auth.authz.TestAuth;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;


/// The controller with [PinotAuthAccessControlFactory]: every request is authenticated by the cluster's method
/// (401 when the credential is missing, of another type or rejected) and authorized by the cluster's authorizer (403
/// when denied), through the real request filter.
public class PinotAuthAccessControlFactoryTest extends ControllerTest {

  @BeforeClass
  public void setUp()
      throws Exception {
    startZk();
    Map<String, Object> config = getDefaultControllerConfiguration();
    config.put(ControllerConf.ACCESS_CONTROL_FACTORY_CLASS, PinotAuthAccessControlFactory.class.getName());
    config.putAll(TestAuth.settings());
    startController(config);
  }

  @AfterClass
  public void tearDown() {
    stopController();
    stopZk();
  }

  @BeforeMethod
  public void reset() {
    TestAuth.Authorizer.ALLOWED.clear();
    TestAuth.Authorizer.SEEN.clear();
  }

  private static Map<String, String> bearer(String token) {
    return Map.of("Authorization", "Bearer " + token);
  }

  @Test
  public void testAuthentication()
      throws Exception {
    String url = _controllerBaseApiUrl + "/tables";
    assertStatus(401, () -> sendGetRequest(url));
    assertStatus(401, () -> sendGetRequest(url, bearer("bad")));
    // A credential of another type than the cluster's method
    assertStatus(401, () -> sendGetRequest(url, Map.of("Authorization", "Basic YWRtaW46dmVyeXNlY3JldA==")));
    // The 401 carries the method's challenge
    HttpResponse<String> response = HttpClient.newHttpClient().send(
        HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString());
    assertEquals(response.statusCode(), 401);
    assertEquals(response.headers().firstValue("WWW-Authenticate").orElse(null), "Bearer realm=\"pinot\"");
    // Health stays open for load balancers
    assertOk(() -> sendGetRequest(_controllerBaseApiUrl + "/health"));
  }

  @Test
  public void testAuthorization() {
    String url = _controllerBaseApiUrl + "/tables";
    // Listing tables names no table, so both checks of the filter are cluster-wide: first the coarse READ, then the
    // endpoint's fine-grained action
    assertStatus(403, () -> sendGetRequest(url, bearer("alice")));
    assertEquals(TestAuth.Authorizer.SEEN, List.of("alice READ on cluster"));
    TestAuth.Authorizer.ALLOWED.add("alice READ on cluster");
    assertStatus(403, () -> sendGetRequest(url, bearer("alice")));
    assertEquals(TestAuth.Authorizer.SEEN, List.of("alice READ on cluster", "alice READ on cluster",
        "alice GetTable on cluster"));
    TestAuth.Authorizer.ALLOWED.add("alice GetTable on cluster");
    assertOk(() -> sendGetRequest(url, bearer("alice")));
    // Another user is still refused
    assertStatus(403, () -> sendGetRequest(url, bearer("bob")));
  }

  @Test
  public void testUiWorkflowAndSignInCheck()
      throws IOException {
    // OAuth 2.0: no password prompt in the UI
    assertTrue(sendGetRequest(_controllerBaseApiUrl + "/auth/info").contains("NONE"));
    assertEquals(sendGetRequest(_controllerBaseApiUrl + "/auth/verify/v2", bearer("alice")).trim(), "true");
    assertEquals(sendGetRequest(_controllerBaseApiUrl + "/auth/verify/v2", bearer("bad")).trim(), "false");
  }

  private static void assertOk(IoRequest request) {
    try {
      request.send();
    } catch (IOException e) {
      fail("Expected success, got " + e);
    }
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
