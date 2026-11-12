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
package org.apache.pinot.minion.api;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collections;
import java.util.Map;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import org.apache.pinot.common.auth.BasicAuthTokenUtils;
import org.apache.pinot.common.config.TlsConfig;
import org.apache.pinot.common.utils.ServiceStatus;
import org.apache.pinot.core.transport.HttpServerThreadPoolConfig;
import org.apache.pinot.core.transport.ListenerConfig;
import org.apache.pinot.minion.MinionAdminApiApplication;
import org.apache.pinot.server.access.AccessControlFactory;
import org.apache.pinot.server.access.BasicAuthAccessFactory;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.CommonConstants;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;


/// The Minion admin API with an access control configured: only the health check is public, every other route needs
/// an administrative principal (401 without valid credentials, 403 without admin permission). Without an access
/// control the API stays open.
public class MinionAdminApiAccessControlTest {
  private static final String INSTANCE_ID = "Minion_localhost_19514";
  private static final String ADMIN = BasicAuthTokenUtils.toBasicAuthToken("admin", "adminPw");
  private static final String READER = BasicAuthTokenUtils.toBasicAuthToken("reader", "readerPw");
  private static final String WRONG = BasicAuthTokenUtils.toBasicAuthToken("admin", "wrong");

  private MinionAdminApiApplication _protectedApp;
  private MinionAdminApiApplication _openApp;
  private WebTarget _protected;
  private WebTarget _open;

  @BeforeClass
  public void setUp()
      throws IOException {
    ServiceStatus.ServiceStatusCallback callback = mock(ServiceStatus.ServiceStatusCallback.class);
    when(callback.getServiceStatus()).thenReturn(ServiceStatus.Status.GOOD);
    ServiceStatus.setServiceStatusCallback(INSTANCE_ID, callback);

    AccessControlFactory basicAuth = new BasicAuthAccessFactory();
    basicAuth.init(new PinotConfiguration(Map.of(
        "principals", "admin,reader",
        "principals.admin.password", "adminPw",
        "principals.admin.permissions", "admin",
        "principals.reader.password", "readerPw",
        "principals.reader.permissions", "read")));
    _protectedApp = new MinionAdminApiApplication(INSTANCE_ID, new PinotConfiguration(), basicAuth);
    _protected = start(_protectedApp);
    _openApp = new MinionAdminApiApplication(INSTANCE_ID, new PinotConfiguration());
    _open = start(_openApp);
  }

  @AfterClass
  public void tearDown() {
    _protectedApp.stop();
    _openApp.stop();
    ServiceStatus.removeServiceStatusCallback(INSTANCE_ID);
  }

  @Test
  public void testHealthIsPublic() {
    assertEquals(get(_protected, "health", null), 200);
  }

  @Test
  public void testAdminRoutesNeedAnAdministrativePrincipal() {
    for (String path : new String[]{"appconfigs", "loggers", "uptime", "start-time", "metrics/gauge/missing"}) {
      assertEquals(get(_protected, path, null), 401, path + " without credentials");
      assertEquals(get(_protected, path, WRONG), 401, path + " with a wrong password");
      assertEquals(get(_protected, path, READER), 403, path + " with a non-admin principal");
      int adminStatus = get(_protected, path, ADMIN);
      assertEquals(adminStatus != 401 && adminStatus != 403, true, path + " as admin: " + adminStatus);
    }
    assertEquals(get(_protected, "appconfigs", ADMIN), 200);
  }

  @Test
  public void testWithoutAccessControlTheApiStaysOpen() {
    assertEquals(get(_open, "appconfigs", null), 200);
    assertEquals(get(_open, "health", null), 200);
  }

  private static int get(WebTarget target, String path, String authorization) {
    Invocation.Builder request = target.path(path).request();
    if (authorization != null) {
      request = request.header(HttpHeaders.AUTHORIZATION, authorization);
    }
    return request.get().getStatus();
  }

  private static WebTarget start(MinionAdminApiApplication app)
      throws IOException {
    int port;
    try (ServerSocket socket = new ServerSocket(0)) {
      port = socket.getLocalPort();
    }
    app.start(Collections.singletonList(new ListenerConfig(CommonConstants.HTTP_PROTOCOL, "0.0.0.0", port,
        CommonConstants.HTTP_PROTOCOL, new TlsConfig(), HttpServerThreadPoolConfig.defaultInstance())));
    return ClientBuilder.newClient().target("http://localhost:" + port);
  }
}
