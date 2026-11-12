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
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.ws.rs.core.HttpHeaders;
import org.apache.pinot.common.exception.HttpErrorStatusException;
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


/// Verifies that the database endpoints are authorized against the database they name ([TargetType#DATABASE]), so an
/// access control can grant or deny one database. Uses an access control that refuses only deleting database `sales`
/// and records every fine-grained check it receives.
public class ControllerDatabaseAuthorizationTest extends ControllerTest {
  private static final List<String> CHECKS = new CopyOnWriteArrayList<>();

  /// Allows everything except deleting database `sales`.
  public static class DenyDeleteSalesAccessControlFactory implements AccessControlFactory {
    private static final AccessControl ACCESS_CONTROL = new AccessControl() {
      // Check every endpoint, as the shipped access controls do, not only those annotated with @Authenticate
      @Override
      public boolean protectAnnotatedOnly() {
        return false;
      }

      @Override
      public boolean hasAccess(HttpHeaders httpHeaders, TargetType targetType, String targetId, String action) {
        CHECKS.add(targetType + ":" + targetId + ":" + action);
        return !(targetType == TargetType.DATABASE && "sales".equals(targetId)
            && Actions.Database.DELETE_DATABASE.equals(action));
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
        DenyDeleteSalesAccessControlFactory.class.getName());
    startController(controllerConfiguration);
  }

  @AfterClass
  public void tearDown() {
    stopController();
    stopZk();
  }

  @Test
  public void testDatabaseEndpointsNameTheirDatabase() {
    // Deleting another database is allowed (dry run, nothing to delete)
    CHECKS.clear();
    assertOk(() -> sendDeleteRequest(_controllerBaseApiUrl + "/databases/marketing?dryRun=true"));
    assertEquals(CHECKS, List.of("DATABASE:marketing:" + Actions.Database.DELETE_DATABASE));

    // Deleting `sales` is refused before anything is touched
    CHECKS.clear();
    assertHttpError(403, () -> sendDeleteRequest(_controllerBaseApiUrl + "/databases/sales?dryRun=true"));
    assertEquals(CHECKS, List.of("DATABASE:sales:" + Actions.Database.DELETE_DATABASE));

    // Quota endpoints carry the database too, including the default database
    CHECKS.clear();
    assertOk(() -> sendGetRequest(_controllerBaseApiUrl + "/databases/default/quotas"));
    assertEquals(CHECKS, List.of("DATABASE:default:" + Actions.Database.GET_DATABASE_QUOTA));

    // Listing databases stays a cluster-level action
    CHECKS.clear();
    assertOk(() -> sendGetRequest(_controllerBaseApiUrl + "/databases"));
    assertEquals(CHECKS, List.of("CLUSTER:null:" + Actions.Cluster.GET_DATABASE));
  }

  private static void assertOk(IoRequest request) {
    try {
      request.send();
    } catch (IOException e) {
      fail("Expected success, got " + e);
    }
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

  @FunctionalInterface
  private interface IoRequest {
    void send()
        throws IOException;
  }
}
