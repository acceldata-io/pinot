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
package org.apache.pinot.controller.util;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.pinot.common.restlet.resources.ValidDocIdsBitmapResponse;
import org.apache.pinot.common.restlet.resources.ValidDocIdsType;
import org.apache.pinot.common.utils.ServiceStatus;
import org.apache.pinot.spi.auth.AuthProvider;
import org.apache.pinot.spi.utils.JsonUtils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;


/**
 * Verifies that validDocIds bitmap fetches, used by upsert compaction and compact-merge, carry the configured
 * service credential once Server admin APIs are access controlled.
 */
public class ServerSegmentMetadataReaderAuthTest {
  private final AtomicReference<String> _receivedAuthorization = new AtomicReference<>();
  private HttpServer _server;
  private String _endpoint;

  @BeforeClass
  public void setUp()
      throws Exception {
    byte[] body = JsonUtils.objectToString(
        new ValidDocIdsBitmapResponse("seg1", "crc1", ValidDocIdsType.SNAPSHOT, new byte[0], "server1",
            ServiceStatus.Status.GOOD)).getBytes(StandardCharsets.UTF_8);
    _server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    _server.createContext("/", exchange -> {
      _receivedAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });
    _server.start();
    _endpoint = "http://localhost:" + _server.getAddress().getPort();
  }

  @AfterClass
  public void tearDown() {
    _server.stop(0);
  }

  @Test
  public void testValidDocIdsBitmapFetchSendsServiceCredential() {
    AuthProvider authProvider = new AuthProvider() {
      @Override
      public Map<String, Object> getRequestHeaders() {
        return Map.of("Authorization", "Basic c2VydmljZTpzZWNyZXQ=");
      }

      @Override
      public String getTaskToken() {
        return "Basic c2VydmljZTpzZWNyZXQ=";
      }
    };
    _receivedAuthorization.set(null);
    ValidDocIdsBitmapResponse response = new ServerSegmentMetadataReader(authProvider)
        .getValidDocIdsBitmapFromServer("myTable_REALTIME", "seg1", _endpoint, ValidDocIdsType.SNAPSHOT.name(), 10_000);
    assertEquals(response.getSegmentCrc(), "crc1");
    assertEquals(_receivedAuthorization.get(), "Basic c2VydmljZTpzZWNyZXQ=");
  }

  @Test
  public void testValidDocIdsBitmapFetchWithoutProviderSendsNoCredential() {
    _receivedAuthorization.set("unset");
    new ServerSegmentMetadataReader((AuthProvider) null)
        .getValidDocIdsBitmapFromServer("myTable_REALTIME", "seg1", _endpoint, ValidDocIdsType.SNAPSHOT.name(), 10_000);
    assertNull(_receivedAuthorization.get());
  }
}
