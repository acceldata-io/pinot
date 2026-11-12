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
package org.apache.pinot.broker.requesthandler;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.helix.model.InstanceConfig;
import org.apache.pinot.broker.broker.AllowAllAccessControlFactory;
import org.apache.pinot.broker.queryquota.QueryQuotaManager;
import org.apache.pinot.broker.routing.manager.BrokerRoutingManager;
import org.apache.pinot.common.config.provider.TableCache;
import org.apache.pinot.common.metrics.BrokerMetrics;
import org.apache.pinot.common.request.BrokerRequest;
import org.apache.pinot.common.request.Expression;
import org.apache.pinot.common.request.PinotQuery;
import org.apache.pinot.common.response.broker.BrokerResponseNative;
import org.apache.pinot.core.routing.RoutingTable;
import org.apache.pinot.core.routing.SegmentsToQuery;
import org.apache.pinot.core.routing.TableRouteInfo;
import org.apache.pinot.core.transport.ServerInstance;
import org.apache.pinot.spi.accounting.ThreadAccountantUtils;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.config.table.TenantConfig;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.eventlistener.query.BrokerQueryEventListenerFactory;
import org.apache.pinot.spi.exception.BadQueryRequestException;
import org.apache.pinot.spi.trace.LoggerConstants;
import org.apache.pinot.spi.trace.RequestContext;
import org.apache.pinot.spi.utils.CommonConstants;
import org.apache.pinot.spi.utils.CommonConstants.Broker;
import org.apache.pinot.sql.parsers.CalciteSqlParser;
import org.apache.pinot.util.TestUtils;
import org.mockito.Mockito;
import org.slf4j.MDC;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class BaseSingleStageBrokerRequestHandlerTest {

  @AfterMethod
  public void cleanupMdc() {
    MDC.clear();
  }

  @Test
  public void testUpdateColumnNames() {
    String query = "SELECT database.my_table.column_name_1st, column_name_2nd from database.my_table";
    PinotQuery pinotQuery = CalciteSqlParser.compileToPinotQuery(query);
    Map<String, String> columnNameMap =
        Map.of("column_name_1st", "column_name_1st", "column_name_2nd", "column_name_2nd");
    BaseSingleStageBrokerRequestHandler.updateColumnNames("database.my_table", pinotQuery, false, columnNameMap);
    Assert.assertEquals(pinotQuery.getSelectList().size(), 2);
    for (Expression expression : pinotQuery.getSelectList()) {
      String columnName = expression.getIdentifier().getName();
      if (columnName.endsWith("column_name_1st")) {
        Assert.assertEquals(columnName, "column_name_1st");
      } else if (columnName.endsWith("column_name_2nd")) {
        Assert.assertEquals(columnName, "column_name_2nd");
      } else {
        Assert.fail("rewritten column name should be column_name_1st or column_name_1st, but is " + columnName);
      }
    }
  }

  @Test
  public void testGetActualColumnNameCaseSensitive() {
    Map<String, String> columnNameMap = new HashMap<>();
    columnNameMap.put("student_name", "student_name");
    String actualColumnName =
        BaseSingleStageBrokerRequestHandler.getActualColumnName("mytable", "mytable.student_name", columnNameMap,
            false);
    Assert.assertEquals(actualColumnName, "student_name");
    Assert.assertEquals(
        BaseSingleStageBrokerRequestHandler.getActualColumnName("db1.mytable", "db1.mytable.student_name",
            columnNameMap, false), "student_name");
    Assert.assertEquals(
        BaseSingleStageBrokerRequestHandler.getActualColumnName("db1.mytable", "mytable.student_name", columnNameMap,
            false), "student_name");
    boolean exceptionThrown = false;
    try {
      BaseSingleStageBrokerRequestHandler.getActualColumnName("mytable", "mytable2.student_name", columnNameMap, false);
      Assert.fail("should throw exception if column is not known");
    } catch (BadQueryRequestException ex) {
      exceptionThrown = true;
    }
    Assert.assertTrue(exceptionThrown, "should throw exception if column is not known");
    exceptionThrown = false;
    try {
      BaseSingleStageBrokerRequestHandler.getActualColumnName("mytable", "MYTABLE.student_name", columnNameMap, false);
      Assert.fail("should throw exception if case sensitive and table name different");
    } catch (BadQueryRequestException ex) {
      exceptionThrown = true;
    }
    Assert.assertTrue(exceptionThrown, "should throw exception if column is not known");
    columnNameMap.put("mytable_student_name", "mytable_student_name");
    String wrongColumnName2 =
        BaseSingleStageBrokerRequestHandler.getActualColumnName("mytable", "mytable_student_name", columnNameMap,
            false);
    Assert.assertEquals(wrongColumnName2, "mytable_student_name");

    columnNameMap.put("mytable", "mytable");
    String wrongColumnName3 =
        BaseSingleStageBrokerRequestHandler.getActualColumnName("mytable", "mytable", columnNameMap, false);
    Assert.assertEquals(wrongColumnName3, "mytable");
  }

  @Test
  public void testGetActualColumnNameCaseInSensitive() {
    Map<String, String> columnNameMap = new HashMap<>();
    columnNameMap.put("student_name", "student_name");
    String actualColumnName =
        BaseSingleStageBrokerRequestHandler.getActualColumnName("mytable", "MYTABLE.student_name", columnNameMap, true);
    Assert.assertEquals(actualColumnName, "student_name");
    Assert.assertEquals(
        BaseSingleStageBrokerRequestHandler.getActualColumnName("db1.MYTABLE", "DB1.mytable.student_name",
            columnNameMap, true), "student_name");
    Assert.assertEquals(
        BaseSingleStageBrokerRequestHandler.getActualColumnName("db1.mytable", "MYTABLE.student_name", columnNameMap,
            true), "student_name");
    boolean exceptionThrown = false;
    try {
      BaseSingleStageBrokerRequestHandler.getActualColumnName("student", "MYTABLE2.student_name", columnNameMap, true);
      Assert.fail("should throw exception if column is not known");
    } catch (BadQueryRequestException ex) {
      exceptionThrown = true;
    }
    Assert.assertTrue(exceptionThrown, "should throw exception if column is not known");
    columnNameMap.put("mytable_student_name", "mytable_student_name");
    String wrongColumnName2 =
        BaseSingleStageBrokerRequestHandler.getActualColumnName("mytable", "MYTABLE_student_name", columnNameMap, true);
    Assert.assertEquals(wrongColumnName2, "mytable_student_name");

    columnNameMap.put("mytable", "mytable");
    String wrongColumnName3 =
        BaseSingleStageBrokerRequestHandler.getActualColumnName("MYTABLE", "mytable", columnNameMap, true);
    Assert.assertEquals(wrongColumnName3, "mytable");
  }

  @Test
  public void testCancelQuery()
      throws Exception {
    String tableName = "myTable_OFFLINE";
    String serviceToken = "server-admin-token";
    AtomicReference<String> receivedAuthorization = new AtomicReference<>();
    HttpServer adminServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    adminServer.createContext("/", exchange -> {
      receivedAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    });
    adminServer.start();

    // Mock pretty much everything until the query can be submitted.
    TableCache tableCache = mock(TableCache.class);
    TableConfig tableCfg = mock(TableConfig.class);
    when(tableCache.getActualTableName(anyString())).thenReturn(tableName);
    TenantConfig tenant = new TenantConfig("tier_BROKER", "tier_SERVER", null);
    when(tableCfg.getTenantConfig()).thenReturn(tenant);
    when(tableCache.getTableConfig(tableName)).thenReturn(tableCfg);
    BrokerRoutingManager routingManager = mock(BrokerRoutingManager.class);
    when(routingManager.routingExists(tableName)).thenReturn(true);
    when(routingManager.getQueryTimeoutMs(tableName)).thenReturn(10000L);
    RoutingTable rt = mock(RoutingTable.class);
    int adminPort = adminServer.getAddress().getPort();
    InstanceConfig serverConfig = new InstanceConfig("Server_localhost_9000");
    serverConfig.setHostName("localhost");
    serverConfig.setPort("9000");
    serverConfig.getRecord().setIntField(CommonConstants.Helix.Instance.ADMIN_PORT_KEY, adminPort);
    when(rt.getServerInstanceToSegmentsMap()).thenReturn(Map.of(new ServerInstance(serverConfig),
        new SegmentsToQuery(List.of("segment01"), List.of())));
    when(routingManager.getRoutingTable(any(), Mockito.anyLong())).thenReturn(rt);
    QueryQuotaManager queryQuotaManager = mock(QueryQuotaManager.class);
    when(queryQuotaManager.acquire(anyString())).thenReturn(true);
    when(queryQuotaManager.acquireDatabase(anyString())).thenReturn(true);
    when(queryQuotaManager.acquireApplication(anyString())).thenReturn(true);
    CountDownLatch latch = new CountDownLatch(1);
    long[] testRequestId = {-1};
    BrokerMetrics.register(mock(BrokerMetrics.class));
    PinotConfiguration config = new PinotConfiguration();
    config.setProperty(Broker.SERVER_ADMIN_AUTH_PREFIX + ".token", serviceToken);
    config.setProperty(Broker.SERVER_ADMIN_AUTH_PREFIX + ".prefix", "Bearer");
    BrokerQueryEventListenerFactory.init(config);
    BaseSingleStageBrokerRequestHandler requestHandler =
        new BaseSingleStageBrokerRequestHandler(config, "testBrokerId", new BrokerRequestIdGenerator(), routingManager,
            new AllowAllAccessControlFactory(), queryQuotaManager, tableCache,
            ThreadAccountantUtils.getNoOpAccountant(), null) {
          @Override
          public void start() {
          }

          @Override
          public void shutDown() {
          }

          @Override
          protected BrokerResponseNative processBrokerRequest(long requestId, BrokerRequest originalBrokerRequest,
              BrokerRequest serverBrokerRequest, TableRouteInfo route, long timeoutMs, ServerStats serverStats,
              RequestContext requestContext)
              throws Exception {
            testRequestId[0] = requestId;
            latch.await();
            return BrokerResponseNative.empty();
          }
        };
    CompletableFuture<Void> queryFuture = CompletableFuture.runAsync(() -> {
      try {
        requestHandler.handleRequest(String.format("select * from %s limit 10", tableName));
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });
    ExecutorService cancellationExecutor = Executors.newSingleThreadExecutor();
    PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
    try {
      TestUtils.waitForCondition((aVoid) -> requestHandler.getRunningServers(testRequestId[0]).size() == 1, 500, 5000,
          "Failed to submit query");
      Map.Entry<Long, String> entry = requestHandler.getRunningQueries().entrySet().iterator().next();
      Assert.assertEquals(entry.getKey().longValue(), testRequestId[0]);
      Assert.assertTrue(entry.getValue().contains("select * from myTable_OFFLINE limit 10"));
      Set<ServerInstance> servers = requestHandler.getRunningServers(testRequestId[0]);
      Assert.assertEquals(servers.size(), 1);
      Assert.assertEquals(servers.iterator().next().getHostname(), "localhost");
      Assert.assertEquals(servers.iterator().next().getPort(), 9000);
      Assert.assertEquals(servers.iterator().next().getInstanceId(), "Server_localhost_9000");
      Assert.assertEquals(servers.iterator().next().getAdminEndpoint(), "http://localhost:" + adminPort);

      Map<String, Integer> serverResponses = new HashMap<>();
      Assert.assertTrue(requestHandler.cancelQuery(testRequestId[0], 3000, cancellationExecutor, connectionManager,
          serverResponses));
      Assert.assertEquals(receivedAuthorization.get(), "Bearer " + serviceToken);
      Assert.assertEquals(serverResponses, Map.of("localhost:" + adminPort, 200));
    } finally {
      latch.countDown();
      try {
        queryFuture.get(5, TimeUnit.SECONDS);
      } finally {
        cancellationExecutor.shutdownNow();
        try {
          connectionManager.close();
        } finally {
          adminServer.stop(0);
        }
      }
    }
  }

  @Test
  public void testAddRoutingPolicyInErrMsg() {
    Assert.assertEquals(BaseSingleStageBrokerRequestHandler.addRoutingPolicyInErrMsg("error1", null, null), "error1");
    Assert.assertEquals(BaseSingleStageBrokerRequestHandler.addRoutingPolicyInErrMsg("error1", "rt_rp", null),
        "error1, with routing policy: rt_rp [realtime]");
    Assert.assertEquals(BaseSingleStageBrokerRequestHandler.addRoutingPolicyInErrMsg("error1", null, "off_rp"),
        "error1, with routing policy: off_rp [offline]");
    Assert.assertEquals(BaseSingleStageBrokerRequestHandler.addRoutingPolicyInErrMsg("error1", "rt_rp", "off_rp"),
        "error1, with routing policy: rt_rp [realtime], off_rp [offline]");
  }

  @Test
  public void testQueryHashRegisteredInMdc() {
    String queryHash = "test_hash_abc123";
    LoggerConstants.QUERY_HASH_KEY.registerInMdc(queryHash);
    String mdcValue = MDC.get(LoggerConstants.QUERY_HASH_KEY.getKey());
    Assert.assertNotNull(mdcValue, "QueryHash should be registered in MDC");
    Assert.assertEquals(mdcValue, queryHash, "MDC should contain the correct queryHash");
  }

  @Test
  public void testQueryHashNotRegisteredWhenNull() {
    String mdcValue = MDC.get(LoggerConstants.QUERY_HASH_KEY.getKey());
    Assert.assertNull(mdcValue, "Null queryHash should not be registered in MDC");
  }

  @Test
  public void testQueryHashAddedToQueryOptions() {
    String query = "SELECT * FROM myTable WHERE col = 100";
    PinotQuery pinotQuery = CalciteSqlParser.compileToPinotQuery(query);
    String queryHash = "generated_hash_xyz";
    pinotQuery.putToQueryOptions(
        CommonConstants.Broker.Request.QueryOptionKey.QUERY_HASH,
        queryHash);
    Assert.assertTrue(pinotQuery.getQueryOptions().containsKey(
        CommonConstants.Broker.Request.QueryOptionKey.QUERY_HASH),
        "QueryHash should be added to queryOptions");
    Assert.assertEquals(
        pinotQuery.getQueryOptions().get(CommonConstants.Broker.Request.QueryOptionKey.QUERY_HASH),
        queryHash,
        "QueryOptions should contain the correct queryHash value");
  }

  @Test
  public void testExtractLookupTableNames() {
    // No lookup at all
    Assert.assertEquals(extractLookupTableNames("SELECT col FROM tbl WHERE col > 1"), Set.of());

    // Select list, filter, group-by, order-by and having
    Assert.assertEquals(extractLookupTableNames("SELECT lookup('dimA', 'c', 'pk', col) FROM tbl"), Set.of("dimA"));
    Assert.assertEquals(extractLookupTableNames("SELECT col FROM tbl WHERE lookup('dimA', 'c', 'pk', col) = 'x'"),
        Set.of("dimA"));
    Assert.assertEquals(
        extractLookupTableNames("SELECT COUNT(*) FROM tbl GROUP BY lookup('dimA', 'c', 'pk', col)"), Set.of("dimA"));
    Assert.assertEquals(extractLookupTableNames("SELECT col FROM tbl ORDER BY lookup('dimA', 'c', 'pk', col)"),
        Set.of("dimA"));
    Assert.assertEquals(
        extractLookupTableNames("SELECT COUNT(*) FROM tbl GROUP BY col HAVING COUNT(*) > 1 AND MAX(col) > 0"),
        Set.of());

    // Wrapped in another function, aliased, and nested inside another lookup's join value
    Assert.assertEquals(extractLookupTableNames("SELECT UPPER(lookup('dimA', 'c', 'pk', col)) AS a FROM tbl"),
        Set.of("dimA"));
    Assert.assertEquals(
        extractLookupTableNames("SELECT lookup('dimA', 'c', 'pk', lookup('dimB', 'c', 'pk', col)) FROM tbl"),
        Set.of("dimA", "dimB"));

    // The function name is canonicalized, so casing in the query must not hide the table
    Assert.assertEquals(extractLookupTableNames("SELECT LOOKUP('dimA', 'c', 'pk', col) FROM tbl"), Set.of("dimA"));

    // Multiple distinct dimension tables
    Assert.assertEquals(extractLookupTableNames(
            "SELECT lookup('dimA', 'c', 'pk', col) FROM tbl WHERE lookup('dimB', 'c', 'pk', col) = 'x'"),
        Set.of("dimA", "dimB"));
  }

  private static Set<String> extractLookupTableNames(String sql) {
    return BaseSingleStageBrokerRequestHandler.extractLookupTableNames(CalciteSqlParser.compileToPinotQuery(sql));
  }
}
