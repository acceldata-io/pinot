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
package org.apache.pinot.plugin.auth.samples;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;


/// A stand-in identity provider for the sample tests, on the JDK's built-in HTTP server: each path answers a scripted
/// status, JSON body and delay, and every request is recorded so tests can check what the handler sent.
final class MockIdpServer implements AutoCloseable {
  /// A recorded request.
  static final class Request {
    final String _method;
    final String _path;
    final String _authorization;
    final String _body;

    Request(String method, String path, String authorization, String body) {
      _method = method;
      _path = path;
      _authorization = authorization;
      _body = body;
    }
  }

  private static final class Answer {
    final int _status;
    final String _body;
    final long _delayMs;

    Answer(int status, String body, long delayMs) {
      _status = status;
      _body = body;
      _delayMs = delayMs;
    }
  }

  private final HttpServer _server;
  private final Map<String, Answer> _answers = new ConcurrentHashMap<>();
  final List<Request> _requests = new CopyOnWriteArrayList<>();

  MockIdpServer()
      throws IOException {
    _server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    _server.setExecutor(Executors.newCachedThreadPool());
    _server.createContext("/", this::handle);
    _server.start();
  }

  String url(String path) {
    return "http://127.0.0.1:" + _server.getAddress().getPort() + path;
  }

  void answer(String path, int status, String body) {
    answer(path, status, body, 0);
  }

  void answer(String path, int status, String body, long delayMs) {
    _answers.put(path, new Answer(status, body, delayMs));
  }

  void reset() {
    _answers.clear();
    _requests.clear();
  }

  private void handle(HttpExchange exchange)
      throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String path = exchange.getRequestURI().getPath();
    _requests.add(new Request(exchange.getRequestMethod(), path,
        exchange.getRequestHeaders().getFirst("Authorization"), body));
    Answer answer = _answers.getOrDefault(path, new Answer(404, "{\"error\":\"not_found\"}", 0));
    if (answer._delayMs > 0) {
      try {
        Thread.sleep(answer._delayMs);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    byte[] bytes = answer._body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(answer._status, bytes.length == 0 ? -1 : bytes.length);
    if (bytes.length > 0) {
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(bytes);
      }
    }
    exchange.close();
  }

  @Override
  public void close() {
    _server.stop(0);
  }
}
