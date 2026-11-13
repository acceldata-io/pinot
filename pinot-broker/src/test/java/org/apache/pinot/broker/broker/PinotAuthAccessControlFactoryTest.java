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
package org.apache.pinot.broker.broker;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.ws.rs.NotAuthorizedException;
import org.apache.pinot.broker.api.AccessControl;
import org.apache.pinot.broker.api.HttpRequesterIdentity;
import org.apache.pinot.broker.grpc.GrpcRequesterIdentity;
import org.apache.pinot.common.request.BrokerRequest;
import org.apache.pinot.common.request.QuerySource;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.core.auth.authz.TestAuth;
import org.apache.pinot.spi.auth.TableAuthorizationResult;
import org.apache.pinot.spi.auth.broker.RequesterIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [PinotAuthAccessControlFactory] on the broker: callers of HTTP and gRPC queries are authenticated by the cluster's
/// method (401 otherwise) and each table read by a query is authorized.
public class PinotAuthAccessControlFactoryTest {

  @BeforeMethod
  public void reset() {
    TestAuth.Authorizer.ALLOWED.clear();
    TestAuth.Authorizer.SEEN.clear();
  }

  private static AccessControl accessControl() {
    PinotAuthAccessControlFactory factory = new PinotAuthAccessControlFactory();
    factory.init(new PinotConfiguration(TestAuth.settings()));
    return factory.create();
  }

  private static RequesterIdentity http(String authorization) {
    HttpRequesterIdentity identity = new HttpRequesterIdentity();
    Multimap<String, String> headers = ArrayListMultimap.create();
    if (authorization != null) {
      headers.put("authorization", authorization);
    }
    identity.setHttpHeaders(headers);
    return identity;
  }

  private static RequesterIdentity grpc(String authorization) {
    GrpcRequesterIdentity identity = new GrpcRequesterIdentity();
    Multimap<String, String> metadata = ArrayListMultimap.create();
    metadata.put("authorization", authorization);
    identity.setMetadata(metadata);
    return identity;
  }

  @Test
  public void testAuthentication() {
    AccessControl accessControl = accessControl();
    NotAuthorizedException missing = expectThrows(NotAuthorizedException.class,
        () -> accessControl.authorize(http(null)));
    assertEquals(missing.getChallenges().get(0), "Bearer realm=\"pinot\"");
    expectThrows(NotAuthorizedException.class, () -> accessControl.authorize(http("Bearer bad")));
    expectThrows(NotAuthorizedException.class, () -> accessControl.authorize(grpc("Basic YWRtaW46YWRtaW4=")));
    assertTrue(accessControl.authorize(http("Bearer alice")).hasAccess());
    assertTrue(accessControl.authorize(grpc("Bearer alice")).hasAccess());
  }

  @Test
  public void testRowFiltersFromNativeRules() {
    Map<String, Object> settings = TestAuth.settings();
    settings.remove("pinot.authz.native.authorizer.class");
    settings.put("pinot.authz.native.rules", "south,all");
    settings.put("pinot.authz.native.rule.south.groups", "south");
    settings.put("pinot.authz.native.rule.south.permissions", "READ");
    settings.put("pinot.authz.native.rule.south.tables", "orders");
    settings.put("pinot.authz.native.rule.south.rowFilter.orders", "region = 'south'");
    settings.put("pinot.authz.native.rule.all.users", "auditor");
    settings.put("pinot.authz.native.rule.all.permissions", "READ");
    settings.put("pinot.authz.native.rule.all.tables", "*");
    PinotAuthAccessControlFactory factory = new PinotAuthAccessControlFactory();
    factory.init(new PinotConfiguration(settings));
    AccessControl accessControl = factory.create();
    assertEquals(accessControl.getRowColFilters(http("Bearer alice:south"), "orders").getRLSFilters().get(),
        List.of("region = 'south'"));
    assertFalse(accessControl.getRowColFilters(http("Bearer auditor"), "orders").getRLSFilters().isPresent());
    assertTrue(accessControl.authorize(http("Bearer alice:south"), Set.of("orders")).hasAccess());
    assertFalse(accessControl.authorize(http("Bearer alice:south"), Set.of("payments")).hasAccess());
  }

  @Test
  public void testQueryWithoutHttpHeaders() {
    AccessControl accessControl = accessControl();
    // gRPC queries: tables are decided through the identity, the header-based query check has nothing to add
    assertTrue(accessControl.hasAccess(null, TargetType.TABLE, "orders", Actions.Table.QUERY));
    assertFalse(accessControl.authorize(grpc("Bearer alice"), Set.of("orders")).hasAccess());
    // Any other action still needs a credential
    expectThrows(NotAuthorizedException.class,
        () -> accessControl.hasAccess(null, TargetType.TABLE, "orders", Actions.Table.GET_SCHEMA));
  }

  @Test
  public void testTablesOfAQuery() {
    AccessControl accessControl = accessControl();
    TestAuth.Authorizer.ALLOWED.add("alice READ on default.orders");
    TableAuthorizationResult result = accessControl.authorize(grpc("Bearer alice"), Set.of("orders", "payments"));
    assertFalse(result.hasAccess());
    assertEquals(result.getFailedTables(), Set.of("payments"));
    assertTrue(accessControl.authorize(http("Bearer alice"), Set.of("orders_OFFLINE")).hasAccess());

    BrokerRequest brokerRequest = new BrokerRequest();
    QuerySource querySource = new QuerySource();
    querySource.setTableName("payments");
    brokerRequest.setQuerySource(querySource);
    assertFalse(accessControl.authorize(http("Bearer alice"), brokerRequest).hasAccess());
    querySource.setTableName("orders");
    assertTrue(accessControl.authorize(http("Bearer alice"), brokerRequest).hasAccess());
  }
}
