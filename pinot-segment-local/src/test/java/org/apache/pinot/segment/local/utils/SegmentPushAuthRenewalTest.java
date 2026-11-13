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
package org.apache.pinot.segment.local.utils;

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
import org.apache.pinot.common.auth.AuthConfig;
import org.apache.pinot.common.auth.AuthProviderUtils;
import org.apache.pinot.spi.auth.AuthProvider;
import org.apache.pinot.spi.ingestion.batch.spec.PinotClusterSpec;
import org.apache.pinot.spi.ingestion.batch.spec.SegmentGenerationJobSpec;
import org.apache.pinot.spi.ingestion.batch.spec.TableSpec;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.yaml.snakeyaml.Yaml;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;


/// Ingestion jobs with an `authConfig` send the credential that is current at each request, so a long push keeps
/// working after its first token expired; jobs with a fixed `authToken` behave as before.
public class SegmentPushAuthRenewalTest {
  private HttpServer _controller;
  private final List<String> _authorizations = new CopyOnWriteArrayList<>();

  /// A provider whose credential changes on every request, standing in for renewed OAuth 2.0 tokens.
  public static class RotatingAuthProvider implements AuthProvider {
    static final AtomicInteger ISSUED = new AtomicInteger();

    public RotatingAuthProvider(AuthConfig authConfig) {
    }

    @Override
    public Map<String, Object> getRequestHeaders() {
      return Map.of("Authorization", getTaskToken());
    }

    @Override
    public String getTaskToken() {
      return "Bearer token-" + ISSUED.incrementAndGet();
    }
  }

  @BeforeClass
  public void start()
      throws IOException {
    _controller = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    _controller.createContext("/", exchange -> {
      _authorizations.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
      exchange.getRequestBody().readAllBytes();
      byte[] body = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });
    _controller.start();
  }

  @AfterClass
  public void stop() {
    _controller.stop(0);
  }

  @BeforeMethod
  public void reset() {
    _authorizations.clear();
    RotatingAuthProvider.ISSUED.set(0);
  }

  private SegmentGenerationJobSpec spec() {
    SegmentGenerationJobSpec spec = new SegmentGenerationJobSpec();
    TableSpec tableSpec = new TableSpec();
    tableSpec.setTableName("orders");
    spec.setTableSpec(tableSpec);
    PinotClusterSpec cluster = new PinotClusterSpec();
    cluster.setControllerURI("http://127.0.0.1:" + _controller.getAddress().getPort());
    spec.setPinotClusterSpecs(new PinotClusterSpec[]{cluster});
    return spec;
  }

  @Test
  public void testEveryRequestCarriesTheCurrentCredential()
      throws Exception {
    SegmentGenerationJobSpec spec = spec();
    spec.setAuthConfig(Map.of("provider.class", RotatingAuthProvider.class.getName()));
    SegmentPushUtils.sendSegmentUris(spec, List.of("file:///tmp/orders_0.tar.gz", "file:///tmp/orders_1.tar.gz"));
    assertEquals(_authorizations.size(), 2);
    assertTrue(_authorizations.get(0).startsWith("Bearer token-"), _authorizations.toString());
    assertTrue(_authorizations.get(1).startsWith("Bearer token-"), _authorizations.toString());
    assertTrue(!_authorizations.get(0).equals(_authorizations.get(1)), _authorizations.toString());
    assertTrue(AuthProviderUtils.currentAuthToken(spec).startsWith("Bearer token-"));
  }

  @Test
  public void testFixedTokenIsUnchanged()
      throws Exception {
    SegmentGenerationJobSpec spec = spec();
    spec.setAuthToken("Basic YWRtaW46dmVyeXNlY3JldA==");
    SegmentPushUtils.sendSegmentUris(spec, List.of("file:///tmp/orders_0.tar.gz", "file:///tmp/orders_1.tar.gz"));
    assertEquals(_authorizations, List.of("Basic YWRtaW46dmVyeXNlY3JldA==", "Basic YWRtaW46dmVyeXNlY3JldA=="));
    assertEquals(AuthProviderUtils.currentAuthToken(spec), "Basic YWRtaW46dmVyeXNlY3JldA==");
  }

  @Test
  public void testAuthConfigInTheJobSpecYaml() {
    String yaml = String.join("\n",
        "jobType: SegmentCreationAndTarPush",
        "authConfig:",
        "  provider.class: org.apache.pinot.plugin.auth.oauth2.OAuthAuthProvider",
        "  source: client_credentials",
        "  token.url: https://idp.example.com/oauth2/token",
        "  client.id: pinot-ingestion",
        "  client.secret: from-the-environment");
    SegmentGenerationJobSpec spec = new Yaml().loadAs(yaml, SegmentGenerationJobSpec.class);
    assertEquals(spec.getAuthConfig().get("provider.class"), "org.apache.pinot.plugin.auth.oauth2.OAuthAuthProvider");
    assertEquals(spec.getAuthConfig().get("client.id"), "pinot-ingestion");
  }
}
