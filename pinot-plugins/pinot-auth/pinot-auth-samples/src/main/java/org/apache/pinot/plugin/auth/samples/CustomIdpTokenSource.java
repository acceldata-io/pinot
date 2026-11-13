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

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.samples.support.HttpCalls;
import org.apache.pinot.plugin.auth.samples.support.Json;
import org.apache.pinot.plugin.auth.samples.support.JsonMapping;
import org.apache.pinot.plugin.auth.spi.AccessToken;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenSource;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Sample token source: obtains tokens for Pinot's own calls between roles from a provider endpoint that is not a
/// standard OAuth 2.0 token endpoint (for a standard one use the built-in client-credentials source). Copy and adapt
/// the request and the response mapping.
///
/// The request is a POST to `token.url`, either a form (`request.format=form`, the default:
/// `grant_type=client_credentials`, plus `scope` when set, client credentials as HTTP Basic) or a JSON body
/// (`request.format=json`: `{"<client.id.field>": ..., "<client.secret.field>": ..., "scope": ...}`). The answer
/// must be 2xx with a JSON object; the token is read from `token.field` (default `access_token`) and the lifetime
/// from `expires.in.field` (seconds, default `expires_in`) or `expires.at.field` (epoch seconds); without either,
/// `default.ttl.seconds` (default 300) applies.
///
/// The client secret is read from the credential store (`client.secret.alias`) at each fetch, so a rotated secret is
/// picked up without a restart. Callers cache the token and refresh it before expiry. Thread-safe after [#init].
public class CustomIdpTokenSource implements OAuthTokenSource {
  private HandlerContext _context;
  private Clock _clock;
  private HttpCalls _http;
  private String _tokenUrl;
  private String _clientId;
  private String _clientSecretAlias;
  @Nullable
  private String _scope;
  private boolean _json;
  private String _clientIdField;
  private String _clientSecretField;
  private String _tokenField;
  private String _expiresInField;
  @Nullable
  private String _expiresAtField;
  private long _defaultTtlSeconds;

  @Override
  public void init(HandlerContext context) {
    PinotConfiguration config = context.getConfig();
    _context = context;
    _clock = context.getClock();
    _http = new HttpCalls(Duration.ofMillis(config.getProperty("http.timeout.ms", 5000L)));
    _tokenUrl = CustomIdpTokenHandler.required(config, "token.url");
    _clientId = CustomIdpTokenHandler.required(config, "client.id");
    _clientSecretAlias = CustomIdpTokenHandler.required(config, "client.secret.alias");
    _scope = CustomIdpTokenHandler.optional(config, "scope");
    String format = config.getProperty("request.format", "form").trim();
    if (!format.equals("form") && !format.equals("json")) {
      throw new IllegalArgumentException("Token source " + context.getName() + ": request.format must be form or json");
    }
    _json = format.equals("json");
    _clientIdField = config.getProperty("client.id.field", "clientId").trim();
    _clientSecretField = config.getProperty("client.secret.field", "clientSecret").trim();
    _tokenField = config.getProperty("token.field", "access_token").trim();
    _expiresInField = config.getProperty("expires.in.field", "expires_in").trim();
    _expiresAtField = CustomIdpTokenHandler.optional(config, "expires.at.field");
    _defaultTtlSeconds = config.getProperty("default.ttl.seconds", 300L);
    // Fail at start, not at the first outbound call, if the secret is missing
    Arrays.fill(_context.getSecretResolver().resolve(_clientSecretAlias), '\0');
  }

  @Override
  public AccessToken fetch() {
    char[] secret = _context.getSecretResolver().resolve(_clientSecretAlias);
    HttpCalls.Response response;
    try {
      if (_json) {
        StringJoiner body = new StringJoiner(",", "{", "}");
        body.add(HttpCalls.jsonString(_clientIdField) + ":" + HttpCalls.jsonString(_clientId));
        body.add(HttpCalls.jsonString(_clientSecretField) + ":" + HttpCalls.jsonString(new String(secret)));
        if (_scope != null) {
          body.add("\"scope\":" + HttpCalls.jsonString(_scope));
        }
        response = _http.postJson(_tokenUrl, body.toString(), Collections.emptyMap());
      } else {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "client_credentials");
        if (_scope != null) {
          form.put("scope", _scope);
        }
        response = _http.postForm(_tokenUrl, form,
            Collections.singletonMap("Authorization", HttpCalls.basic(_clientId, secret)));
      }
    } catch (IOException | RuntimeException e) {
      throw new IllegalStateException("Token source " + _context.getName() + ": cannot reach the token endpoint", e);
    } finally {
      Arrays.fill(secret, '\0');
    }
    if (!response.isOk()) {
      // Do not include the body: some providers echo the request, secret included
      throw new IllegalStateException("Token source " + _context.getName() + ": token endpoint answered "
          + response.getStatus());
    }
    Map<String, Object> answer;
    try {
      answer = Json.parseObject(response.getBody());
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("Token source " + _context.getName() + ": token endpoint did not answer a JSON "
          + "object");
    }
    String token = JsonMapping.getString(answer, _tokenField);
    if (token == null) {
      throw new IllegalStateException("Token source " + _context.getName() + ": no '" + _tokenField + "' in the "
          + "answer");
    }
    Instant now = _clock.instant();
    Instant expiresAt;
    Long expiresAtSeconds = _expiresAtField != null ? JsonMapping.getLong(answer, _expiresAtField) : null;
    Long expiresIn = JsonMapping.getLong(answer, _expiresInField);
    if (expiresAtSeconds != null) {
      expiresAt = Instant.ofEpochSecond(expiresAtSeconds);
    } else if (expiresIn != null) {
      expiresAt = now.plusSeconds(expiresIn);
    } else {
      expiresAt = now.plusSeconds(_defaultTtlSeconds);
    }
    return new AccessToken(token, expiresAt);
  }
}
