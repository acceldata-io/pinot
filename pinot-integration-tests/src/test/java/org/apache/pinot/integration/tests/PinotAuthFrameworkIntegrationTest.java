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
package org.apache.pinot.integration.tests;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import org.apache.pinot.client.PinotDriver;
import org.apache.pinot.common.config.GrpcConfig;
import org.apache.pinot.common.exception.HttpErrorStatusException;
import org.apache.pinot.common.proto.Broker;
import org.apache.pinot.common.utils.grpc.BrokerGrpcQueryClient;
import org.apache.pinot.spi.config.table.TableType;
import org.apache.pinot.spi.data.FieldSpec;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.CommonConstants;
import org.apache.pinot.spi.utils.NetUtils;
import org.apache.pinot.spi.utils.builder.TableConfigBuilder;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;
import static org.testng.Assert.fail;


/// A whole cluster on the pluggable authentication and authorization framework: every role uses its
/// `PinotAuth*` access control with the `basic` method and native rules. Checks every entry point over HTTP, JDBC and
/// gRPC: a missing, wrong-type or rejected credential gets 401 (gRPC `UNAUTHENTICATED`) with the method's challenge, a
/// valid one reaches the authorizer, and Pinot's own calls between roles work with the service account.
public class PinotAuthFrameworkIntegrationTest extends ClusterTest {
  private static final String TABLE = "authTable";
  private static final String ADMIN = basic("admin", "verysecret");
  private static final String ANALYST = basic("analyst", "secret");
  private static final String OUTSIDER = basic("outsider", "nope");
  private static final String REPORTING = basic("reporting", "report");

  private int _brokerGrpcPort;

  private static String basic(String user, String password) {
    return "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
  }

  /// The cluster-wide settings, the same on every role.
  private static void addFrameworkSettings(Map<String, Object> properties) {
    properties.put("pinot.auth.method", "basic");
    properties.put("pinot.auth.basic.principals", "admin,analyst,outsider,reporting");
    properties.put("pinot.auth.basic.principals.reporting.password", "report");
    properties.put("pinot.auth.basic.principals.admin.password", "verysecret");
    properties.put("pinot.auth.basic.principals.admin.service.account", "true");
    properties.put("pinot.auth.basic.principals.analyst.password", "secret");
    properties.put("pinot.auth.basic.principals.analyst.groups", "analysts");
    properties.put("pinot.auth.basic.principals.outsider.password", "nope");
    properties.put("pinot.authz.native.rules", "analysts,reporting");
    // JDBC finds brokers through a cluster-wide call, so its users need READ on every table
    properties.put("pinot.authz.native.rule.reporting.users", "reporting");
    properties.put("pinot.authz.native.rule.reporting.permissions", "READ");
    properties.put("pinot.authz.native.rule.reporting.tables", "*");
    properties.put("pinot.authz.native.rule.analysts.groups", "analysts");
    properties.put("pinot.authz.native.rule.analysts.permissions", "READ");
    properties.put("pinot.authz.native.rule.analysts.tables", TABLE);
  }

  private static void addFrameworkSettings(PinotConfiguration configuration) {
    Map<String, Object> properties = new HashMap<>();
    addFrameworkSettings(properties);
    properties.forEach(configuration::setProperty);
  }

  @Override
  protected void overrideControllerConf(Map<String, Object> properties) {
    addFrameworkSettings(properties);
    properties.put("controller.admin.access.control.factory.class",
        "org.apache.pinot.controller.api.access.PinotAuthAccessControlFactory");
    properties.put("controller.segment.fetcher.auth.token", ADMIN);
    properties.put("controller.server.admin.auth.token", ADMIN);
    properties.put("controller.broker.auth.token", ADMIN);
  }

  @Override
  protected void overrideBrokerConf(PinotConfiguration brokerConf) {
    addFrameworkSettings(brokerConf);
    brokerConf.setProperty("pinot.broker.access.control.class",
        "org.apache.pinot.broker.broker.PinotAuthAccessControlFactory");
    brokerConf.setProperty("pinot.broker.server.admin.auth.token", ADMIN);
    _brokerGrpcPort = NetUtils.findOpenPort(18000 + (int) (Math.random() * 1000));
    brokerConf.setProperty(CommonConstants.Broker.Grpc.KEY_OF_GRPC_PORT, _brokerGrpcPort);
  }

  @Override
  protected void overrideServerConf(PinotConfiguration serverConf) {
    addFrameworkSettings(serverConf);
    serverConf.setProperty("pinot.server.admin.access.control.factory.class",
        "org.apache.pinot.server.access.PinotAuthAccessFactory");
    serverConf.setProperty("pinot.server.segment.fetcher.auth.token", ADMIN);
    serverConf.setProperty("pinot.server.segment.uploader.auth.token", ADMIN);
    serverConf.setProperty("pinot.server.instance.auth.token", ADMIN);
  }

  @Override
  protected void overrideMinionConf(PinotConfiguration minionConf) {
    addFrameworkSettings(minionConf);
    minionConf.setProperty("pinot.minion.admin.access.control.factory.class",
        "org.apache.pinot.server.access.PinotAuthAccessFactory");
    minionConf.setProperty("segment.fetcher.auth.token", ADMIN);
    minionConf.setProperty("task.auth.token", ADMIN);
  }

  @Override
  protected Map<String, String> getControllerRequestClientHeaders() {
    return Map.of("Authorization", ADMIN);
  }

  @BeforeClass
  public void setUp()
      throws Exception {
    startZk();
    startController();
    startBroker();
    startServer();
    startMinion();
    Schema schema = new Schema.SchemaBuilder().setSchemaName(TABLE)
        .addSingleValueDimension("city", FieldSpec.DataType.STRING).build();
    addSchema(schema);
    addTableConfig(new TableConfigBuilder(TableType.OFFLINE).setTableName(TABLE).build());
  }

  @AfterClass(alwaysRun = true)
  public void tearDown()
      throws Exception {
    stopMinion();
    stopServer();
    stopBroker();
    stopController();
    stopZk();
  }

  private static Map<String, String> auth(String value) {
    return Map.of("Authorization", value);
  }

  private String brokerQueryUrl() {
    return "http://localhost:" + getRandomBrokerPort() + "/query/sql";
  }

  private static String query(String table) {
    return "{\"sql\":\"SELECT COUNT(*) FROM " + table + "\"}";
  }

  @Test
  public void testHttpAuthenticationAtEveryRole()
      throws Exception {
    String[] urls = {
        "http://localhost:" + getControllerPort() + "/tables",
        "http://localhost:" + getRandomBrokerPort() + "/debug/routingTable/" + TABLE,
        "http://localhost:" + getServerAdminApiPort() + "/tables",
        _minionBaseApiUrl + "/appconfigs"};
    HttpClient client = HttpClient.newHttpClient();
    for (String url : urls) {
      for (String credential : new String[]{null, "Basic YWRtaW46d3Jvbmc=", "Bearer some-token"}) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).GET();
        if (credential != null) {
          request.header("Authorization", credential);
        }
        HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(response.statusCode(), 401, url + " with " + credential);
        assertEquals(response.headers().firstValue("WWW-Authenticate").orElse(null), "Basic realm=\"pinot\"", url);
      }
      // The service account passes everywhere
      HttpResponse<String> ok = client.send(HttpRequest.newBuilder(URI.create(url)).header("Authorization", ADMIN)
          .GET().build(), HttpResponse.BodyHandlers.ofString());
      assertEquals(ok.statusCode(), 200, url + ": " + ok.body());
    }
    // Health stays open for load balancers
    assertEquals(client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + getControllerPort() + "/health"))
        .GET().build(), HttpResponse.BodyHandlers.ofString()).statusCode(), 200);
  }

  @Test
  public void testHttpQueriesAreAuthorizedPerTable()
      throws Exception {
    assertTrue(sendPostRequest(brokerQueryUrl(), query(TABLE), auth(ANALYST)).contains("resultTable"));
    assertStatus(401, () -> sendPostRequest(brokerQueryUrl(), query(TABLE)));
    assertStatus(403, () -> sendPostRequest(brokerQueryUrl(), query(TABLE), auth(OUTSIDER)));
    // Controller: the analyst reads its table, not the cluster (apache/pinot#14595)
    sendGetRequest("http://localhost:" + getControllerPort() + "/tables/" + TABLE + "/schema", auth(ANALYST));
    assertStatus(403, () -> sendGetRequest("http://localhost:" + getControllerPort() + "/tables", auth(ANALYST)));
  }

  @Test
  public void testJdbc()
      throws Exception {
    Properties properties = new Properties();
    properties.setProperty(PinotDriver.INFO_HEADERS + ".Authorization", REPORTING);
    try (Connection connection = new PinotDriver().connect("jdbc:pinot://localhost:" + getControllerPort(),
        properties); Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery("SELECT COUNT(*) FROM " + TABLE)) {
      assertTrue(resultSet.next());
      assertEquals(resultSet.getLong(1), 0L);
    }
    Properties wrong = new Properties();
    wrong.setProperty(PinotDriver.INFO_HEADERS + ".Authorization", basic("reporting", "wrong"));
    expectThrows(SQLException.class, () -> {
      try (Connection connection = new PinotDriver().connect("jdbc:pinot://localhost:" + getControllerPort(), wrong);
          Statement statement = connection.createStatement()) {
        statement.executeQuery("SELECT COUNT(*) FROM " + TABLE);
      }
    });
  }

  @Test
  public void testBrokerGrpc() {
    BrokerGrpcQueryClient client = new BrokerGrpcQueryClient("localhost", _brokerGrpcPort, new GrpcConfig(Map.of()));
    try {
      assertTrue(grpc(client, ANALYST, TABLE).hasNext());
      assertGrpcStatus(Status.Code.UNAUTHENTICATED, () -> grpc(client, null, TABLE).next());
      assertGrpcStatus(Status.Code.UNAUTHENTICATED, () -> grpc(client, basic("analyst", "wrong"), TABLE).next());
      assertGrpcStatus(Status.Code.PERMISSION_DENIED, () -> grpc(client, OUTSIDER, TABLE).next());
    } finally {
      client.close();
    }
  }

  private static Iterator<Broker.BrokerResponse> grpc(BrokerGrpcQueryClient client, String authorization,
      String table) {
    Broker.BrokerRequest.Builder request = Broker.BrokerRequest.newBuilder().setSql("SELECT COUNT(*) FROM " + table);
    if (authorization != null) {
      request.putMetadata("authorization", authorization);
    }
    return client.submit(request.build());
  }

  private static void assertGrpcStatus(Status.Code expected, Runnable call) {
    StatusRuntimeException e = expectThrows(StatusRuntimeException.class, call::run);
    assertEquals(e.getStatus().getCode(), expected, e.getMessage());
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
