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
package org.apache.pinot.client.controller;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;


/// The JDBC controller transport (broker discovery, metadata) obtains its headers again for every request, so a
/// supplier of fresh OAuth 2.0 tokens keeps a long-lived connection working.
public class PinotControllerTransportHeadersTest {
  private HttpServer _server;
  private final List<String> _authorizations = new CopyOnWriteArrayList<>();

  @BeforeClass
  public void start()
      throws IOException {
    _server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    _server.createContext("/", exchange -> {
      _authorizations.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
      byte[] body = "{\"tables\":[]}".getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });
    _server.start();
  }

  @AfterClass
  public void stop() {
    _server.stop(0);
  }

  @Test
  public void testHeadersSupplierIsCalledForEveryRequest()
      throws Exception {
    AtomicInteger tokens = new AtomicInteger();
    PinotControllerTransportFactory factory = new PinotControllerTransportFactory();
    factory.setHeaders(Map.of("Authorization", "Bearer fixed"));
    factory.setHeadersSupplier(() -> Map.of("Authorization", "Bearer tok-" + tokens.incrementAndGet()));
    PinotControllerTransport transport = factory.buildTransport();
    String controller = "127.0.0.1:" + _server.getAddress().getPort();
    transport.getAllTables(controller);
    transport.getAllTables(controller);
    transport.close();
    assertEquals(_authorizations, List.of("Bearer tok-1", "Bearer tok-2"));
  }
}
