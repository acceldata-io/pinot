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
package org.apache.pinot.server.access;

import java.util.Map;
import javax.ws.rs.NotAuthorizedException;
import org.apache.pinot.core.auth.authz.TestAuth;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [PinotAuthAccessFactory] on the server and Minion: 401 with the method's challenge, admin API needs cluster ADMIN,
/// data access needs READ on the table.
public class PinotAuthAccessFactoryTest {

  @BeforeMethod
  public void reset() {
    TestAuth.Authorizer.ALLOWED.clear();
    TestAuth.Authorizer.SEEN.clear();
  }

  private static AccessControl accessControl() {
    PinotAuthAccessFactory factory = new PinotAuthAccessFactory();
    factory.init(new PinotConfiguration(TestAuth.settings()));
    return factory.create();
  }

  private static GrpcRequesterIdentity bearer(String token) {
    return new GrpcRequesterIdentity(Map.of("authorization", "Bearer " + token));
  }

  @Test
  public void testUnauthenticated() {
    AccessControl accessControl = accessControl();
    NotAuthorizedException missing = expectThrows(NotAuthorizedException.class,
        () -> accessControl.authorizeAdminAccess(new GrpcRequesterIdentity(Map.of())));
    assertEquals(missing.getChallenges().get(0), "Bearer realm=\"pinot\"");
    NotAuthorizedException rejected = expectThrows(NotAuthorizedException.class,
        () -> accessControl.hasDataAccess(bearer("bad"), "orders_OFFLINE"));
    assertTrue(String.valueOf(rejected.getChallenges().get(0)).contains("invalid_token"));
  }

  @Test
  public void testAdminAndDataAccess() {
    AccessControl accessControl = accessControl();
    TestAuth.Authorizer.ALLOWED.add("ops ADMIN on cluster");
    TestAuth.Authorizer.ALLOWED.add("alice READ on default.orders");
    assertTrue(accessControl.authorizeAdminAccess(bearer("ops")).hasAccess());
    assertFalse(accessControl.authorizeAdminAccess(bearer("alice")).hasAccess());
    assertTrue(accessControl.hasDataAccess(bearer("alice"), "orders_REALTIME"));
    assertFalse(accessControl.hasDataAccess(bearer("alice"), "payments_OFFLINE"));
    assertTrue(accessControl.isAuthorizedChannel(null));
  }
}
