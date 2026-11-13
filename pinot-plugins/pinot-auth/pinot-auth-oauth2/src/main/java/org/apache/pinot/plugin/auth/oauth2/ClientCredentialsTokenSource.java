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

import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.IOException;
import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AccessToken;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenSource;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Tokens for Pinot's own calls by the OAuth 2.0 client credentials grant (RFC 6749 section 4.4).
///
/// Settings:
/// - `token.url`, or `issuer` to read `token_endpoint` from `<issuer>/.well-known/openid-configuration`
/// - `client.id` (required); the client secret comes from the secret resolver under `client.secret.alias` (default
///   `client.secret`)
/// - `client.auth` = `basic` (default, HTTP Basic) or `post` (form fields)
/// - `scope` (optional, space-separated), `audience` and `resource` (optional, sent as form fields for providers that
///   need them, e.g. RFC 8707)
/// - `token.field` (default `access_token`; `id_token` for providers that issue ID tokens to clients),
///   `default.ttl.seconds` (default 300) when the answer has no `expires_in`, `http.timeout.ms` (default 5000)
///
/// Thread-safe after [#init].
public class ClientCredentialsTokenSource implements OAuthTokenSource {
  public static final String TYPE = "client_credentials";

  private String _name;
  private HandlerContext _context;
  private ProviderHttp _http;
  private String _tokenUrl;
  private String _clientId;
  private String _clientSecretAlias;
  private boolean _basicClientAuth;
  private Map<String, String> _extraForm;
  private String _tokenField;
  private long _defaultTtlSeconds;

  @Override
  public void init(HandlerContext context) {
    PinotConfiguration config = context.getConfig();
    _name = context.getName();
    _context = context;
    _http = new ProviderHttp(config.getProperty("http.timeout.ms", 5000L), ProviderHttp.DEFAULT_MAX_RESPONSE_BYTES);
    _clientId = required(config, "client.id");
    _clientSecretAlias = config.getProperty("client.secret.alias", "client.secret").trim();
    // Resolve once at start so a missing secret fails the start, not the first internal call
    context.getSecretResolver().resolve(_clientSecretAlias);
    String clientAuth = config.getProperty("client.auth", "basic").trim();
    if (!clientAuth.equals("basic") && !clientAuth.equals("post")) {
      throw new IllegalArgumentException("Token source " + _name + ": client.auth must be basic or post");
    }
    _basicClientAuth = clientAuth.equals("basic");
    _extraForm = new LinkedHashMap<>();
    for (String key : new String[]{"scope", "audience", "resource"}) {
      String value = trimToNull(config.getProperty(key));
      if (value != null) {
        _extraForm.put(key, value);
      }
    }
    _tokenField = config.getProperty("token.field", "access_token").trim();
    _defaultTtlSeconds = config.getProperty("default.ttl.seconds", 300L);
    String tokenUrl = trimToNull(config.getProperty("token.url"));
    _tokenUrl = tokenUrl != null ? tokenUrl : discover(trimToNull(config.getProperty("issuer")));
  }

  @Override
  public AccessToken fetch() {
    char[] secret = _context.getSecretResolver().resolve(_clientSecretAlias);
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "client_credentials");
    form.putAll(_extraForm);
    Map<String, String> headers = new LinkedHashMap<>();
    if (_basicClientAuth) {
      headers.put("Authorization", ProviderHttp.basic(_clientId, secret));
    } else {
      form.put("client_id", _clientId);
      form.put("client_secret", new String(secret));
    }
    ProviderHttp.Answer answer;
    try {
      answer = _http.postForm(_tokenUrl, form, headers);
    } catch (IOException e) {
      throw new IllegalStateException("Token source " + _name + ": cannot reach the token endpoint", e);
    }
    if (!answer.isOk()) {
      // Never include the body: some providers echo the request
      throw new IllegalStateException("Token source " + _name + ": token endpoint answered " + answer._status);
    }
    Map<String, Object> json;
    try {
      json = JSONObjectUtils.parse(answer._body);
    } catch (ParseException e) {
      throw new IllegalStateException("Token source " + _name + ": token endpoint answer is not JSON");
    }
    Object token = json.get(_tokenField);
    if (!(token instanceof String) || ((String) token).isEmpty()) {
      throw new IllegalStateException("Token source " + _name + ": no '" + _tokenField + "' in the answer");
    }
    Object expiresIn = json.get("expires_in");
    long seconds = expiresIn instanceof Number ? ((Number) expiresIn).longValue() : _defaultTtlSeconds;
    return new AccessToken((String) token, _context.getClock().instant().plusSeconds(seconds));
  }

  private String discover(@Nullable String issuer) {
    if (issuer == null) {
      throw new IllegalArgumentException("Token source " + _name + ": set token.url or issuer");
    }
    String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
    try {
      ProviderHttp.Answer answer = _http.get(base + "/.well-known/openid-configuration", Collections.emptyMap());
      Object endpoint = answer.isOk() ? JSONObjectUtils.parse(answer._body).get("token_endpoint") : null;
      if (!(endpoint instanceof String)) {
        throw new IllegalStateException("Token source " + _name + ": no token_endpoint in the discovery document of '"
            + issuer + "'");
      }
      return (String) endpoint;
    } catch (IOException | ParseException e) {
      throw new IllegalStateException("Token source " + _name + ": cannot load the discovery document of '" + issuer
          + "'", e);
    }
  }

  private String required(PinotConfiguration config, String key) {
    String value = trimToNull(config.getProperty(key));
    if (value == null) {
      throw new IllegalArgumentException("Token source " + _name + ": " + key + " is required");
    }
    return value;
  }

  @Nullable
  private static String trimToNull(@Nullable String value) {
    return value == null || value.trim().isEmpty() ? null : value.trim();
  }
}
