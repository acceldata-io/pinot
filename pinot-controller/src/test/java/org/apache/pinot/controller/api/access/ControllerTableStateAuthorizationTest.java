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
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.ws.rs.core.HttpHeaders;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.pinot.common.exception.HttpErrorStatusException;
import org.apache.pinot.common.utils.http.HttpClient;
import org.apache.pinot.controller.ControllerConf;
import org.apache.pinot.controller.helix.ControllerTest;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;


/// Verifies that `PUT /tables/{tableName}/state` authorizes the action matching the requested state, so an access
/// control can allow enabling a table while denying disabling it. Uses an access control that refuses only
/// [Actions.Table#DISABLE_TABLE] and records every fine-grained check it receives.
public class ControllerTableStateAuthorizationTest extends ControllerTest {
  private static final String TABLE = "stateTable";
  private static final List<String> CHECKS = new CopyOnWriteArrayList<>();

  /// Allows everything except disabling a table.
  public static class DenyDisableTableAccessControlFactory implements AccessControlFactory {
    private static final AccessControl ACCESS_CONTROL = new AccessControl() {
      @Override
      public boolean hasAccess(HttpHeaders httpHeaders, TargetType targetType, String targetId, String action) {
        CHECKS.add(targetType + ":" + targetId + ":" + action);
        return !Actions.Table.DISABLE_TABLE.equals(action);
      }
    };

    @Override
    public AccessControl create() {
      return ACCESS_CONTROL;
    }
  }

  @BeforeClass
  public void setUp()
      throws Exception {
    startZk();
    Map<String, Object> controllerConfiguration = getDefaultControllerConfiguration();
    controllerConfiguration.put(ControllerConf.ACCESS_CONTROL_FACTORY_CLASS,
        DenyDisableTableAccessControlFactory.class.getName());
    startController(controllerConfiguration);
  }

  @AfterClass
  public void tearDown() {
    stopController();
    stopZk();
  }

  @Test
  public void testStateChangeAuthorizesTheRequestedAction() {
    String url = _controllerBaseApiUrl + "/tables/" + TABLE + "/state?type=offline&state=";

    // Enabling is allowed: the request passes authorization and reaches the resource, which reports the missing table.
    CHECKS.clear();
    assertHttpError(404, () -> sendTextPutRequest(url + "enable", Map.of()));
    assertEquals(CHECKS, List.of("TABLE:" + TABLE + ":" + Actions.Table.ENABLE_TABLE));

    // Disabling is denied before the table is looked up.
    CHECKS.clear();
    assertHttpError(403, () -> sendTextPutRequest(url + "disable", Map.of()));
    assertEquals(CHECKS, List.of("TABLE:" + TABLE + ":" + Actions.Table.DISABLE_TABLE));

    // An unknown state is rejected without an authorization decision.
    CHECKS.clear();
    assertHttpError(400, () -> sendTextPutRequest(url + "bogus", Map.of()));
    assertTrue(CHECKS.isEmpty(), "Unexpected authorization checks: " + CHECKS);
  }

  private static void assertHttpError(int expectedStatus, IoRequest request) {
    try {
      request.send();
      fail("Expected HTTP status " + expectedStatus);
    } catch (IOException e) {
      assertTrue(e.getCause() instanceof HttpErrorStatusException, "Unexpected failure: " + e);
      assertEquals(((HttpErrorStatusException) e.getCause()).getStatusCode(), expectedStatus);
    }
  }

  /// `PUT /tables/{tableName}/state` consumes `text/plain`; the JSON helpers would get HTTP 415.
  private static String sendTextPutRequest(String url, Map<String, String> headers)
      throws IOException {
    try {
      return HttpClient.wrapAndThrowHttpException(getHttpClient().sendPutRequest(new URI(url),
          new StringEntity("", ContentType.TEXT_PLAIN), headers)).getResponse();
    } catch (URISyntaxException | HttpErrorStatusException e) {
      throw new IOException(e);
    }
  }

  @FunctionalInterface
  private interface IoRequest {
    void send()
        throws IOException;
  }
}
