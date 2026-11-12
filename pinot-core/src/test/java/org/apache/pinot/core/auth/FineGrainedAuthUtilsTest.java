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
package org.apache.pinot.core.auth;

import java.lang.reflect.Method;
import java.net.URI;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import org.apache.pinot.spi.utils.CommonConstants;
import org.testng.annotations.Test;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;
import static org.testng.Assert.fail;

public class FineGrainedAuthUtilsTest {

  @Test
  public void testFindRawTargetId()
      throws Exception {
    MultivaluedMap<String, String> pathParams = new MultivaluedHashMap<>();
    MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
    Method tableMethod = TestResource.class.getDeclaredMethod("getTable");
    Method tableQueryMethod = TestResource.class.getDeclaredMethod("getTableByQuery", String.class);
    Authorize tableAuth = tableMethod.getAnnotation(Authorize.class);
    Authorize tableQueryAuth = tableQueryMethod.getAnnotation(Authorize.class);
    Authorize clusterAuth = getAnnotatedMethod().getAnnotation(Authorize.class);

    pathParams.putSingle("tableName", "pathTable");
    assertEquals(FineGrainedAuthUtils.findRawTargetId(tableAuth, tableMethod, pathParams, queryParams), "pathTable");

    pathParams.clear();
    queryParams.putSingle("tableName", "queryTable");
    // The annotation names tableName, but getTable never binds it, so the query value is not trusted.
    assertNull(FineGrainedAuthUtils.findRawTargetId(tableAuth, tableMethod, pathParams, queryParams));
    assertEquals(FineGrainedAuthUtils.findRawTargetId(tableQueryAuth, tableQueryMethod, pathParams, queryParams),
        "queryTable");
    assertNull(FineGrainedAuthUtils.findRawTargetId(clusterAuth, getAnnotatedMethod(), pathParams, queryParams));

    queryParams.clear();
    assertNull(FineGrainedAuthUtils.findRawTargetId(tableAuth, tableMethod, pathParams, queryParams));
  }

  @Test
  public void testValidateFineGrainedAuthIgnoresUndeclaredTableQueryParam()
      throws Exception {
    FineGrainedAccessControl ac = mock(FineGrainedAccessControl.class);
    when(ac.hasAccess(any(HttpHeaders.class), any(), any(), any()))
        .thenReturn(true);

    UriInfo mockUriInfo = mock(UriInfo.class);
    MultivaluedMap<String, String> pathParams = new MultivaluedHashMap<>();
    MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
    queryParams.putSingle("tableName", "callerPicked");
    when(mockUriInfo.getPathParameters()).thenReturn(pathParams);
    when(mockUriInfo.getQueryParameters()).thenReturn(queryParams);
    when(mockUriInfo.getRequestUri()).thenReturn(URI.create("http://localhost/tables"));
    HttpHeaders mockHttpHeaders = mock(HttpHeaders.class);

    Method unboundTableMethod = TestResource.class.getDeclaredMethod("getTable");
    try {
      FineGrainedAuthUtils.validateFineGrainedAuth(unboundTableMethod, mockUriInfo, mockHttpHeaders, ac);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException e) {
      assertTrue(e.getMessage().contains("Missing required table parameter"));
      assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
    }
    verify(ac, never())
        .hasAccess(any(HttpHeaders.class), any(), any(), any());
  }

  @Test
  public void testValidateFineGrainedAuthAllowsDeclaredTableQueryParam()
      throws Exception {
    FineGrainedAccessControl ac = mock(FineGrainedAccessControl.class);
    when(ac.hasAccess(any(HttpHeaders.class), any(), any(), any()))
        .thenReturn(true);

    UriInfo mockUriInfo = mock(UriInfo.class);
    MultivaluedMap<String, String> pathParams = new MultivaluedHashMap<>();
    MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
    queryParams.putSingle("tableName", "ownedTable");
    when(mockUriInfo.getPathParameters()).thenReturn(pathParams);
    when(mockUriInfo.getQueryParameters()).thenReturn(queryParams);
    HttpHeaders mockHttpHeaders = mock(HttpHeaders.class);

    Method declaredTableMethod = TestResource.class.getDeclaredMethod("getTableByQuery", String.class);
    FineGrainedAuthUtils.validateFineGrainedAuth(declaredTableMethod, mockUriInfo, mockHttpHeaders, ac);
    verify(ac).hasAccess(mockHttpHeaders, TargetType.TABLE, "ownedTable", "getTable");
  }

  @Test
  public void testValidateFineGrainedAuthAllowed() {
    FineGrainedAccessControl ac = mock(FineGrainedAccessControl.class);
    when(ac.hasAccess(any(HttpHeaders.class), any(), any(), any()))
        .thenReturn(true);

    UriInfo mockUriInfo = mock(UriInfo.class);
    HttpHeaders mockHttpHeaders = mock(HttpHeaders.class);

    FineGrainedAuthUtils.validateFineGrainedAuth(getAnnotatedMethod(), mockUriInfo, mockHttpHeaders, ac);
  }

  @Test
  public void testValidateFineGrainedAuthDenied() {
    FineGrainedAccessControl ac = mock(FineGrainedAccessControl.class);
    when(ac.hasAccess(any(HttpHeaders.class), any(), any(), any()))
        .thenReturn(false);

    UriInfo mockUriInfo = mock(UriInfo.class);
    HttpHeaders mockHttpHeaders = mock(HttpHeaders.class);

    try {
      FineGrainedAuthUtils.validateFineGrainedAuth(getAnnotatedMethod(), mockUriInfo, mockHttpHeaders, ac);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException e) {
      assertTrue(e.getMessage().contains("Access denied to getCluster in the cluster"));
      assertEquals(e.getResponse().getStatus(), Response.Status.FORBIDDEN.getStatusCode());
    }
  }

  @Test
  public void testValidateFineGrainedAuthWithNoSuchMethodError() {
    FineGrainedAccessControl ac = mock(FineGrainedAccessControl.class);
    when(ac.hasAccess(any(HttpHeaders.class), any(), any(), any()))
        .thenThrow(new NoSuchMethodError("Method not found"));

    UriInfo mockUriInfo = mock(UriInfo.class);
    HttpHeaders mockHttpHeaders = mock(HttpHeaders.class);

    try {
      FineGrainedAuthUtils.validateFineGrainedAuth(getAnnotatedMethod(), mockUriInfo, mockHttpHeaders, ac);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException e) {
      assertTrue(e.getMessage().contains("Failed to check for access"));
      assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
    }
  }

  @Test
  public void testMissingTableParameterIsBadRequest() {
    UriInfo mockUriInfo = mock(UriInfo.class);
    when(mockUriInfo.getPathParameters()).thenReturn(new MultivaluedHashMap<>());
    when(mockUriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
    when(mockUriInfo.getRequestUri()).thenReturn(URI.create("http://localhost/v2/segments"));

    WebApplicationException exception = expectThrows(WebApplicationException.class,
        () -> FineGrainedAuthUtils.validateFineGrainedAuth(getTableAnnotatedMethod(), mockUriInfo,
            mock(HttpHeaders.class), mock(FineGrainedAccessControl.class)));

    assertEquals(exception.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
    assertTrue(exception.getMessage().contains("Missing required table parameter 'tableName'"));
  }

  @Test
  public void testInvalidTableParameterIsBadRequest() {
    UriInfo mockUriInfo = mock(UriInfo.class);
    MultivaluedHashMap<String, String> queryParameters = new MultivaluedHashMap<>();
    queryParameters.putSingle("tableName", "databaseB.testTable");
    when(mockUriInfo.getPathParameters()).thenReturn(new MultivaluedHashMap<>());
    when(mockUriInfo.getQueryParameters()).thenReturn(queryParameters);
    when(mockUriInfo.getRequestUri()).thenReturn(URI.create("http://localhost/v2/segments"));
    HttpHeaders headers = mock(HttpHeaders.class);
    when(headers.getHeaderString(CommonConstants.DATABASE)).thenReturn("databaseA");

    WebApplicationException exception = expectThrows(WebApplicationException.class,
        () -> FineGrainedAuthUtils.validateFineGrainedAuth(getTableAnnotatedMethod(), mockUriInfo, headers,
            mock(FineGrainedAccessControl.class)));

    assertEquals(exception.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
    assertTrue(exception.getMessage().contains("Invalid table parameter 'tableName'"));
  }

  @Test
  public void testDatabaseTargetPassesTheDatabaseName() {
    for (String database : new String[]{"sales", "default"}) {
      FineGrainedAccessControl ac = mock(FineGrainedAccessControl.class);
      when(ac.hasAccess(any(HttpHeaders.class), any(), any(), any())).thenReturn(true);
      HttpHeaders headers = mock(HttpHeaders.class);
      FineGrainedAuthUtils.validateFineGrainedAuth(getDatabaseMethod("deleteDatabase"),
          databaseUri(pathParams(database), new MultivaluedHashMap<>()), headers, ac);
      verify(ac).hasAccess(headers, TargetType.DATABASE, database, "deleteDatabase");
    }
  }

  @Test
  public void testDatabaseTargetDenied() {
    FineGrainedAccessControl ac = mock(FineGrainedAccessControl.class);
    when(ac.hasAccess(any(HttpHeaders.class), any(), any(), any())).thenReturn(false);
    WebApplicationException e = expectThrows(WebApplicationException.class,
        () -> FineGrainedAuthUtils.validateFineGrainedAuth(getDatabaseMethod("deleteDatabase"),
            databaseUri(pathParams("sales"), new MultivaluedHashMap<>()), mock(HttpHeaders.class), ac));
    assertEquals(e.getResponse().getStatus(), Response.Status.FORBIDDEN.getStatusCode());
    assertTrue(e.getMessage().contains("Access denied to deleteDatabase for database: sales"), e.getMessage());
  }

  @Test
  public void testMissingDatabaseParameterIsBadRequest() {
    // A caller-supplied query parameter the method does not declare must not stand in for the database
    MultivaluedHashMap<String, String> query = new MultivaluedHashMap<>();
    query.putSingle("databaseName", "sales");
    FineGrainedAccessControl ac = mock(FineGrainedAccessControl.class);
    WebApplicationException e = expectThrows(WebApplicationException.class,
        () -> FineGrainedAuthUtils.validateFineGrainedAuth(getDatabaseMethod("deleteDatabase"),
            databaseUri(new MultivaluedHashMap<>(), query), mock(HttpHeaders.class), ac));
    assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
    assertTrue(e.getMessage().contains("Missing required database parameter 'databaseName'"), e.getMessage());
    verify(ac, never()).hasAccess(any(HttpHeaders.class), any(), any(), any());
  }

  @Test
  public void testDatabaseTargetWithoutParamNameIsServerError() {
    WebApplicationException e = expectThrows(WebApplicationException.class,
        () -> FineGrainedAuthUtils.validateFineGrainedAuth(getDatabaseMethod("databaseWithoutParam"),
            databaseUri(pathParams("sales"), new MultivaluedHashMap<>()), mock(HttpHeaders.class),
            mock(FineGrainedAccessControl.class)));
    assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
  }

  private static MultivaluedHashMap<String, String> pathParams(String database) {
    MultivaluedHashMap<String, String> params = new MultivaluedHashMap<>();
    params.putSingle("databaseName", database);
    return params;
  }

  private static UriInfo databaseUri(MultivaluedHashMap<String, String> pathParams,
      MultivaluedHashMap<String, String> queryParams) {
    UriInfo uriInfo = mock(UriInfo.class);
    when(uriInfo.getPathParameters()).thenReturn(pathParams);
    when(uriInfo.getQueryParameters()).thenReturn(queryParams);
    when(uriInfo.getRequestUri()).thenReturn(URI.create("http://localhost/databases/x"));
    return uriInfo;
  }

  private static Method getDatabaseMethod(String name) {
    try {
      return TestResource.class.getDeclaredMethod(name);
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
  }

  static class TestResource {
    @Authorize(targetType = TargetType.CLUSTER, action = "getCluster")
    void getCluster() {
    }

    @Authorize(targetType = TargetType.DATABASE, paramName = "databaseName", action = "deleteDatabase")
    void deleteDatabase() {
    }

    @Authorize(targetType = TargetType.DATABASE, action = "deleteDatabase")
    void databaseWithoutParam() {
    }

    @Authorize(targetType = TargetType.TABLE, paramName = "tableName", action = "getTable")
    void getTable() {
    }

    @Authorize(targetType = TargetType.TABLE, paramName = "tableName", action = "uploadSegment")
    void uploadSegment(@QueryParam("tableName") String tableName) {
    }

    @Authorize(targetType = TargetType.TABLE, paramName = "tableName", action = "getTable")
    void getTableByQuery(@QueryParam("tableName") String tableName) {
    }
  }

  private Method getAnnotatedMethod() {
    try {
      return TestResource.class.getDeclaredMethod("getCluster");
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
  }

  private Method getTableAnnotatedMethod() {
    try {
      return TestResource.class.getDeclaredMethod("uploadSegment", String.class);
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
  }
}
