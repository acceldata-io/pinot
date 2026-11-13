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
package org.apache.pinot.plugin.auth.samples.support;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.StringJoiner;


/// Calls to an identity provider over HTTP with the JDK client: fixed connect and request timeouts, no redirects
/// (a redirect from a validation endpoint is treated as a failure, never followed with the token), and a cap on the
/// response size. Thread-safe; create one per handler and reuse it.
public final class HttpCalls {
  /// Responses larger than this are refused, so a misbehaving endpoint cannot exhaust memory.
  public static final int MAX_RESPONSE_CHARS = 256 * 1024;

  private final HttpClient _client;
  private final Duration _timeout;

  public HttpCalls(Duration timeout) {
    _timeout = timeout;
    _client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
  }

  /// A provider response: status code and body.
  public static final class Response {
    private final int _status;
    private final String _body;

    Response(int status, String body) {
      _status = status;
      _body = body;
    }

    public int getStatus() {
      return _status;
    }

    public String getBody() {
      return _body;
    }

    public boolean isOk() {
      return _status >= 200 && _status < 300;
    }
  }

  /// GET with optional extra headers.
  ///
  /// @throws IOException if the provider cannot be reached, times out or answers too much
  public Response get(String url, Map<String, String> headers)
      throws IOException {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).timeout(_timeout).GET();
    headers.forEach(builder::header);
    return send(builder.build());
  }

  /// POST of a form (`application/x-www-form-urlencoded`) with optional extra headers.
  ///
  /// @throws IOException if the provider cannot be reached, times out or answers too much
  public Response postForm(String url, Map<String, String> form, Map<String, String> headers)
      throws IOException {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).timeout(_timeout)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(formBody(form)));
    headers.forEach(builder::header);
    return send(builder.build());
  }

  /// POST of a JSON body with optional extra headers.
  ///
  /// @throws IOException if the provider cannot be reached, times out or answers too much
  public Response postJson(String url, String json, Map<String, String> headers)
      throws IOException {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).timeout(_timeout)
        .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(json));
    headers.forEach(builder::header);
    return send(builder.build());
  }

  /// `Basic base64(user:password)` for client authentication at the provider.
  public static String basic(String user, char[] password) {
    String pair = user + ":" + new String(password);
    return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
  }

  /// Encodes a form body.
  public static String formBody(Map<String, String> form) {
    StringJoiner joiner = new StringJoiner("&");
    form.forEach((key, value) -> joiner.add(
        URLEncoder.encode(key, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)));
    return joiner.toString();
  }

  /// Quotes a string as a JSON string value.
  public static String jsonString(String value) {
    StringBuilder sb = new StringBuilder("\"");
    for (char c : value.toCharArray()) {
      if (c == '"' || c == '\\') {
        sb.append('\\').append(c);
      } else if (c < 0x20) {
        sb.append(String.format("\\u%04x", (int) c));
      } else {
        sb.append(c);
      }
    }
    return sb.append('"').toString();
  }

  private Response send(HttpRequest request)
      throws IOException {
    HttpResponse<String> response;
    try {
      response = _client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted calling " + request.uri().getHost(), e);
    }
    String body = response.body() == null ? "" : response.body();
    if (body.length() > MAX_RESPONSE_CHARS) {
      throw new IOException("Response from " + request.uri().getHost() + " is too large");
    }
    return new Response(response.statusCode(), body);
  }
}
