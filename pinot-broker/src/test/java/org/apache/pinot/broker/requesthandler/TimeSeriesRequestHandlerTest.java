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

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import org.apache.pinot.broker.api.AccessControl;
import org.apache.pinot.broker.api.HttpRequesterIdentity;
import org.apache.pinot.broker.broker.AccessControlFactory;
import org.apache.pinot.broker.broker.BasicAuthAccessControlFactory;
import org.apache.pinot.common.auth.BasicAuthTokenUtils;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.spi.auth.TableAuthorizationResult;
import org.apache.pinot.spi.auth.broker.RequesterIdentity;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.exception.QueryErrorCode;
import org.apache.pinot.spi.exception.QueryException;
import org.apache.pinot.tsdb.spi.plan.BaseTimeSeriesPlanNode;
import org.apache.pinot.tsdb.spi.plan.LeafTimeSeriesPlanNode;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;


public class TimeSeriesRequestHandlerTest {

  private AutoCloseable _mocks;

  @Mock
  private LeafTimeSeriesPlanNode _leafNode;
  @Mock
  private Schema _tableSchema;

  @BeforeMethod
  public void setUp() {
    _mocks = MockitoAnnotations.openMocks(this);

    // Set up default mock behaviors
    lenient().when(_leafNode.getTableName()).thenReturn("metrics_REALTIME");
    lenient().when(_tableSchema.hasColumn("ts")).thenReturn(true);
    lenient().when(_tableSchema.hasColumn("colA")).thenReturn(true);
    lenient().when(_tableSchema.hasColumn("colB")).thenReturn(true);
    lenient().when(_tableSchema.hasColumn("colC")).thenReturn(true);
  }

  @Test
  void testValidateColumnNamesSuccess() {
    when(_leafNode.getTimeColumn()).thenReturn("ts");
    when(_leafNode.getValueExpression()).thenReturn("colA / colB");
    when(_leafNode.getGroupByExpressions()).thenReturn(List.of(
        "colB",
        "DIMENSION(colC)",
        "case when colA > 0 then 'positive' else 'non-negative' end",
        "lower(colB)"
        ));
    when(_leafNode.getFilterExpression()).thenReturn("colB > 10 AND colA < 5 AND ts > 12345");

    try {
      TimeSeriesRequestHandler.validateColumnNames(_leafNode, _tableSchema);
    } catch (Exception e) {
      fail("Should not throw exception when all columns are valid: " + e.getMessage());
    }
  }

  @Test
  void testValidateColumnNamesSuccessWithTimeColumnExpression() {
    when(_leafNode.getTimeColumn()).thenReturn("ts / 1000");
    when(_leafNode.getValueExpression()).thenReturn("colA + 100");
    when(_leafNode.getGroupByExpressions()).thenReturn(List.of(
        "colB",
        "DIMENSION(colC)",
        "case when colA > 0 then 'positive' else 'non-negative' end",
        "lower(colB)"
    ));
    when(_leafNode.getFilterExpression()).thenReturn("colB > 10 AND colA < 5 AND ts > 12345");

    try {
      TimeSeriesRequestHandler.validateColumnNames(_leafNode, _tableSchema);
    } catch (Exception e) {
      fail("Should not throw exception when all columns are valid: " + e.getMessage());
    }
  }

  @Test
  public void testValidateColumnNamesWhenInvalidTimeColumn() {
    when(_leafNode.getTimeColumn()).thenReturn("invalid_ts_column");
    when(_tableSchema.hasColumn("invalid_ts_column")).thenReturn(false);

    try {
      TimeSeriesRequestHandler.validateColumnNames(_leafNode, _tableSchema);
      fail("Expected a QueryException to be thrown");
    } catch (QueryException e) {
      assertEquals(e.getErrorCode(), QueryErrorCode.UNKNOWN_COLUMN);
      assertTrue(e.getMessage().contains("Column 'invalid_ts_column' in expression 'invalid_ts_column' not found"));
    } catch (Exception e) {
      fail("Expected QueryException, but got " + e.getClass().getName(), e);
    }
  }

  @Test
  public void testValidateColumnNamesWhenInvalidValueExpressionColumn() {
    when(_leafNode.getTimeColumn()).thenReturn("ts");
    when(_leafNode.getValueExpression()).thenReturn("SUM(invalid_value_col)");
    when(_tableSchema.hasColumn("invalid_value_col")).thenReturn(false);

    try {
      TimeSeriesRequestHandler.validateColumnNames(_leafNode, _tableSchema);
      fail("Expected a QueryException to be thrown");
    } catch (QueryException e) {
      assertEquals(e.getErrorCode(), QueryErrorCode.UNKNOWN_COLUMN);
      assertTrue(e.getMessage().contains("Column 'invalid_value_col' in expression 'SUM(invalid_value_col)'"));
    } catch (Exception e) {
      fail("Expected QueryException, but got " + e.getClass().getName(), e);
    }
  }

  @Test
  public void testValidateColumnNamesWhenInvalidGroupByColumn() {
    when(_leafNode.getTimeColumn()).thenReturn("ts");
    when(_leafNode.getValueExpression()).thenReturn("SUM(colA)");
    when(_leafNode.getGroupByExpressions()).thenReturn(List.of("colB", "invalid_group_col"));
    when(_tableSchema.hasColumn("invalid_group_col")).thenReturn(false);

    try {
      TimeSeriesRequestHandler.validateColumnNames(_leafNode, _tableSchema);
      fail("Expected a QueryException to be thrown");
    } catch (QueryException e) {
      assertEquals(e.getErrorCode(), QueryErrorCode.UNKNOWN_COLUMN);
      assertTrue(e.getMessage().contains("Column 'invalid_group_col' in expression 'invalid_group_col'"));
    } catch (Exception e) {
      fail("Expected QueryException, but got " + e.getClass().getName(), e);
    }
  }

  @Test
  public void testValidateColumnNamesWhenInvalidFilterColumn() {
    when(_leafNode.getTimeColumn()).thenReturn("ts");
    when(_leafNode.getValueExpression()).thenReturn("SUM(colA)");
    when(_leafNode.getGroupByExpressions()).thenReturn(List.of("colB"));
    when(_leafNode.getFilterExpression()).thenReturn("colB > 10 AND invalid_filter_col = 'foo'");
    when(_tableSchema.hasColumn("invalid_filter_col")).thenReturn(false);

    try {
      TimeSeriesRequestHandler.validateColumnNames(_leafNode, _tableSchema);
      fail("Expected a QueryException to be thrown");
    } catch (QueryException e) {
      assertEquals(e.getErrorCode(), QueryErrorCode.UNKNOWN_COLUMN);
      assertTrue(e.getMessage().contains("Column 'invalid_filter_col' in filter expression"));
    } catch (Exception e) {
      fail("Expected QueryException, but got " + e.getClass().getName(), e);
    }
  }

  @Test
  public void testValidateColumnSuccessWhenEmptyFilterColumn() {
    when(_leafNode.getTimeColumn()).thenReturn("ts");
    when(_leafNode.getValueExpression()).thenReturn("SUM(colA)");
    when(_leafNode.getGroupByExpressions()).thenReturn(List.of("colB"));
    when(_leafNode.getFilterExpression()).thenReturn("");
    when(_tableSchema.hasColumn("invalid_filter_col")).thenReturn(false);

    try {
      TimeSeriesRequestHandler.validateColumnNames(_leafNode, _tableSchema);
    } catch (Exception e) {
      fail("Did not expect exception, but got " + e.getClass().getName(), e);
    }
  }

  @Test
  public void testValidateColumnNamesWhenComplexExpressionsAllValid() {
    when(_leafNode.getTimeColumn()).thenReturn("ts + 10");
    when(_leafNode.getValueExpression()).thenReturn("colA + colB/100");
    when(_leafNode.getGroupByExpressions()).thenReturn(List.of("DATETRUNC('day', ts)", "CONCAT(colC, '-')"));
    when(_leafNode.getFilterExpression()).thenReturn("ts > 100 AND colA != 50");

    try {
      TimeSeriesRequestHandler.validateColumnNames(_leafNode, _tableSchema);
    } catch (Exception e) {
      fail("Should pass with complex expressions if all columns are valid: " + e.getMessage());
    }
  }

  /// A broker BasicAuth access control: admin sees every table, "user" only `metrics`, "rlsUser" `metrics` with a
  /// row filter.
  private static AccessControl basicAuthAccessControl() {
    Map<String, Object> config = new HashMap<>();
    config.put("principals", "admin,user,rlsUser");
    config.put("principals.admin.password", "adminPw");
    config.put("principals.user.password", "userPw");
    config.put("principals.user.tables", "metrics");
    config.put("principals.rlsUser.password", "rlsPw");
    config.put("principals.rlsUser.tables", "metrics");
    config.put("principals.rlsUser.metrics.rls", "region = 'eu'");
    AccessControlFactory factory = new BasicAuthAccessControlFactory();
    factory.init(new PinotConfiguration(config));
    return factory.create();
  }

  private static HttpRequesterIdentity identity(String user, String password) {
    Multimap<String, String> headers = ArrayListMultimap.create();
    headers.put("authorization", BasicAuthTokenUtils.toBasicAuthToken(user, password));
    HttpRequesterIdentity identity = new HttpRequesterIdentity();
    identity.setHttpHeaders(headers);
    return identity;
  }

  private static void assertDenied(Runnable check, int expectedStatus, String expectedMessagePart) {
    try {
      check.run();
      fail("Expected HTTP " + expectedStatus);
    } catch (WebApplicationException e) {
      assertEquals(e.getResponse().getStatus(), expectedStatus);
      if (expectedMessagePart != null) {
        assertTrue(e.getMessage().contains(expectedMessagePart), e.getMessage());
      }
    }
  }

  @Test
  public void testTableAccessFollowsTableScope() {
    AccessControl accessControl = basicAuthAccessControl();
    HttpRequesterIdentity user = identity("user", "userPw");

    // Table names carry a type suffix in time-series queries; the scope lists raw names.
    TimeSeriesRequestHandler.checkTableAccess(accessControl, user, null, List.of("metrics_REALTIME"), true);
    TimeSeriesRequestHandler.checkTableAccess(accessControl, user, null, List.of("metrics"), true);

    // Any table outside the scope denies the whole query, and the denied table is named.
    assertDenied(() -> TimeSeriesRequestHandler.checkTableAccess(accessControl, user, null,
        List.of("other_OFFLINE"), true), 403, "[other]");
    assertDenied(() -> TimeSeriesRequestHandler.checkTableAccess(accessControl, user, null,
        List.of("metrics_REALTIME", "other_OFFLINE"), true), 403, "[other]");

    // An unrestricted principal reads every table.
    TimeSeriesRequestHandler.checkTableAccess(accessControl, identity("admin", "adminPw"), null,
        List.of("metrics_REALTIME", "other_OFFLINE"), true);
  }

  @Test
  public void testUnknownCredentialsAreRejected() {
    assertDenied(() -> TimeSeriesRequestHandler.checkTableAccess(basicAuthAccessControl(), identity("user", "wrong"),
        null, List.of("metrics_REALTIME"), false), 401, null);
  }

  @Test
  public void testRowFilteredTableIsRejectedOnlyWithRowColumnAuth() {
    AccessControl accessControl = basicAuthAccessControl();
    HttpRequesterIdentity rlsUser = identity("rlsUser", "rlsPw");
    // The engine cannot apply the row filter, so with row/column level auth on the query is refused.
    assertDenied(() -> TimeSeriesRequestHandler.checkTableAccess(accessControl, rlsUser, null,
        List.of("metrics_REALTIME"), true), 403, "row-level filters");
    // With row/column level auth off, row filters are not in force on any query path.
    TimeSeriesRequestHandler.checkTableAccess(accessControl, rlsUser, null, List.of("metrics_REALTIME"), false);
  }

  @Test
  public void testFineGrainedTableDecisionIsHonored() {
    // An access control whose table decision comes from the fine-grained hook (as an external authorizer's would);
    // the requester-level check allows everything.
    AccessControl denyOther = new AccessControl() {
      @Override
      public TableAuthorizationResult authorize(RequesterIdentity requesterIdentity, Set<String> tables) {
        return TableAuthorizationResult.success();
      }

      @Override
      public boolean hasAccess(HttpHeaders httpHeaders, TargetType targetType, String targetId, String action) {
        return !"other".equals(targetId) || !Actions.Table.QUERY.equals(action);
      }
    };
    TimeSeriesRequestHandler.checkTableAccess(denyOther, null, null, List.of("metrics_REALTIME"), false);
    assertDenied(() -> TimeSeriesRequestHandler.checkTableAccess(denyOther, null, null, List.of("other_OFFLINE"),
        false), 403, "[other]");
  }

  @Test
  public void testCollectTableNamesWalksTheWholePlan() {
    LeafTimeSeriesPlanNode leafA = mock(LeafTimeSeriesPlanNode.class);
    when(leafA.getTableName()).thenReturn("metrics_REALTIME");
    when(leafA.getInputs()).thenReturn(List.of());
    LeafTimeSeriesPlanNode leafB = mock(LeafTimeSeriesPlanNode.class);
    when(leafB.getTableName()).thenReturn("other_OFFLINE");
    when(leafB.getInputs()).thenReturn(List.of());
    BaseTimeSeriesPlanNode inner = mock(BaseTimeSeriesPlanNode.class);
    when(inner.getInputs()).thenReturn(List.of(leafB));
    BaseTimeSeriesPlanNode root = mock(BaseTimeSeriesPlanNode.class);
    when(root.getInputs()).thenReturn(List.of(leafA, inner));
    assertEquals(TimeSeriesRequestHandler.collectTableNames(root), Set.of("metrics_REALTIME", "other_OFFLINE"));
  }
}
