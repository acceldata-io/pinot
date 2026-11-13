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
package org.apache.pinot.plugin.auth.oauth2;

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
import javax.annotation.Nullable;
import javax.net.ssl.SSLContext;


/// HTTP calls from token handlers to an identity provider: connect and request timeouts, no redirects (a redirect is
/// never followed with a token or a client secret), and a response size cap. Thread-safe; one per handler.
final class ProviderHttp {
  static final int DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;

  private final HttpClient _client;
  private final Duration _timeout;
  private final int _maxResponseBytes;

  ProviderHttp(long timeoutMs, int maxResponseBytes) {
    this(timeoutMs, maxResponseBytes, null);
  }

  /// @param sslContext TLS context for the provider (own key for mutual TLS, own trust store), or `null` for the JVM's
  ProviderHttp(long timeoutMs, int maxResponseBytes, @Nullable SSLContext sslContext) {
    _timeout = Duration.ofMillis(timeoutMs);
    _maxResponseBytes = maxResponseBytes;
    HttpClient.Builder builder =
        HttpClient.newBuilder().connectTimeout(_timeout).followRedirects(HttpClient.Redirect.NEVER);
    if (sslContext != null) {
      builder.sslContext(sslContext);
    }
    _client = builder.build();
  }

  /// Status and body of a provider answer.
  static final class Answer {
    final int _status;
    final String _body;

    Answer(int status, String body) {
      _status = status;
      _body = body;
    }

    boolean isOk() {
      return _status >= 200 && _status < 300;
    }
  }

  long getTimeoutMs() {
    return _timeout.toMillis();
  }

  Answer get(String url, Map<String, String> headers)
      throws IOException {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).timeout(_timeout).GET();
    headers.forEach(builder::header);
    return send(builder.build());
  }

  Answer postForm(String url, Map<String, String> form, Map<String, String> headers)
      throws IOException {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).timeout(_timeout)
        .header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(form(form)));
    headers.forEach(builder::header);
    return send(builder.build());
  }

  Answer send(HttpRequest request)
      throws IOException {
    HttpResponse<byte[]> response;
    try {
      response = _client.send(request, HttpResponse.BodyHandlers.ofByteArray());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted calling " + request.uri().getHost(), e);
    }
    byte[] body = response.body() == null ? new byte[0] : response.body();
    if (body.length > _maxResponseBytes) {
      throw new IOException("Answer from " + request.uri().getHost() + " exceeds " + _maxResponseBytes + " bytes");
    }
    return new Answer(response.statusCode(), new String(body, StandardCharsets.UTF_8));
  }

  static String form(Map<String, String> form) {
    StringJoiner joiner = new StringJoiner("&");
    form.forEach((key, value) -> joiner.add(
        URLEncoder.encode(key, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)));
    return joiner.toString();
  }

  /// HTTP Basic client authentication as in RFC 6749 section 2.3.1: id and secret form-encoded, then Base64.
  static String basic(String clientId, char[] secret) {
    String pair = URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
        + URLEncoder.encode(new String(secret), StandardCharsets.UTF_8);
    return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
  }
}
