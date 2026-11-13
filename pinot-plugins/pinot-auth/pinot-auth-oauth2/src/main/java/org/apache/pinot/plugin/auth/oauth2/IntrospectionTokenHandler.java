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
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Validates tokens with the provider's token introspection endpoint (RFC 7662), for opaque tokens or when the
/// provider must confirm that a token has not been revoked. The token is sent in a POST with Pinot's client
/// credentials; the answer must say `active: true`.
///
/// Answers are cached by the SHA-256 of the token, so the provider is asked once per token per period: an active
/// token for `cache.ttl.seconds` (default 60) but never past its `exp`; an inactive token for
/// `negative.cache.seconds` (default 10), so a client retrying a bad token does not flood the provider. Provider
/// failures are never cached. At most `cache.max.entries` (default 10000) answers are kept.
///
/// Settings (under `pinot.auth.oauth2.handler.<name>.`):
/// - `introspection.url`, or `issuer` to read `introspection_endpoint` from `<issuer>/.well-known/openid-configuration`
/// - `issuer`: also routes JWT access tokens of this issuer here and, when the answer carries `iss`, must match it
/// - `client.id` (required), `client.secret.alias` (required, credential-store alias), `client.auth` = `basic`
///   (default, HTTP Basic) or `post` (`client_id` / `client_secret` form fields)
/// - `token.type.hint` (default `access_token`), `audiences` (optional comma list; the answer's `aud` must contain one)
/// - `user.claim` (default `username`, falling back to `sub`), `groups.claim` (default `groups`)
/// - `http.timeout.ms` (default 5000), `http.size.limit.bytes` (default 65536)
///
/// Thread-safe after [#init].
final class IntrospectionTokenHandler implements OAuthTokenHandler {
  static final String TYPE = "introspection";
  private static final Logger LOGGER = LoggerFactory.getLogger(IntrospectionTokenHandler.class);

  private String _name;
  private String _challenge;
  private Clock _clock;
  private ProviderHttp _http;
  private String _url;
  @Nullable
  private String _issuer;
  private String _clientId;
  private char[] _clientSecret;
  private boolean _basicClientAuth;
  private String _tokenTypeHint;
  private Set<String> _audiences;
  private String _userClaim;
  private String _groupsClaim;
  private TokenResultCache _cache;

  @Override
  public void init(HandlerContext context) {
    PinotConfiguration config = context.getConfig();
    _name = context.getName();
    _clock = context.getClock();
    _challenge = AuthenticationException.challengeFor(AuthMethod.OAUTH2) + ", error=\"invalid_token\"";
    _http = new ProviderHttp(config.getProperty("http.timeout.ms", 5000L),
        config.getProperty("http.size.limit.bytes", ProviderHttp.DEFAULT_MAX_RESPONSE_BYTES));
    _issuer = trimToNull(config.getProperty("issuer"));
    _clientId = required(config, "client.id");
    // Kept for the life of the handler: the secret is needed for every call to the provider
    _clientSecret = context.getSecretResolver().resolve(required(config, "client.secret.alias"));
    String clientAuth = config.getProperty("client.auth", "basic").trim();
    if (!clientAuth.equals("basic") && !clientAuth.equals("post")) {
      throw new IllegalArgumentException("Handler " + _name + ": client.auth must be basic or post");
    }
    _basicClientAuth = clientAuth.equals("basic");
    _tokenTypeHint = config.getProperty("token.type.hint", "access_token").trim();
    _audiences = JwtTokenHandler.csv(config.getProperty("audiences", ""));
    _userClaim = config.getProperty("user.claim", "username").trim();
    _groupsClaim = config.getProperty("groups.claim", "groups").trim();
    _cache = new TokenResultCache(config);
    String url = trimToNull(config.getProperty("introspection.url"));
    _url = url != null ? url : discover();
    LOGGER.info("Introspection handler {} ready: endpoint={}, issuer={}, client={}", _name, _url, _issuer, _clientId);
  }

  @Nullable
  String getIssuer() {
    return _issuer;
  }

  @Nullable
  @Override
  public TokenIdentity validate(String token) {
    String key = TokenResultCache.key(token);
    long nowMs = _clock.millis();
    TokenResultCache.Entry cached = _cache.get(key, nowMs);
    if (cached != null) {
      if (cached._identity == null) {
        throw reject("not active (cached)");
      }
      return cached._identity;
    }
    Map<String, Object> answer = introspect(token);
    if (!Boolean.TRUE.equals(answer.get("active"))) {
      _cache.putRejected(key, nowMs);
      throw reject("not active");
    }
    TokenIdentity identity = toIdentity(answer, nowMs);
    _cache.putAccepted(key, identity, nowMs);
    return identity;
  }

  private Map<String, Object> introspect(String token) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("token", token);
    form.put("token_type_hint", _tokenTypeHint);
    Map<String, String> headers = new LinkedHashMap<>();
    if (_basicClientAuth) {
      headers.put("Authorization", ProviderHttp.basic(_clientId, _clientSecret));
    } else {
      form.put("client_id", _clientId);
      form.put("client_secret", new String(_clientSecret));
    }
    ProviderHttp.Answer answer;
    try {
      answer = _http.postForm(_url, form, headers);
    } catch (IOException | RuntimeException e) {
      LOGGER.warn("Handler {}: introspection call failed: {}", _name, e.toString());
      throw unavailable("introspection call failed", e);
    }
    if (answer._status == 401 || answer._status == 403) {
      // The provider refuses Pinot's client credentials: a configuration problem, not the user's token
      LOGGER.error("Handler {}: the introspection endpoint refuses Pinot's client credentials (HTTP {}); check "
          + "client.id and the secret under client.secret.alias", _name, answer._status);
      throw unavailable("introspection endpoint refuses Pinot's client credentials", null);
    }
    if (!answer.isOk()) {
      throw unavailable("introspection endpoint answered " + answer._status, null);
    }
    try {
      return JSONObjectUtils.parse(answer._body);
    } catch (ParseException e) {
      throw unavailable("introspection answer is not a JSON object", null);
    }
  }

  private TokenIdentity toIdentity(Map<String, Object> answer, long nowMs) {
    Object iss = answer.get("iss");
    if (_issuer != null && iss != null && !_issuer.equals(iss)) {
      throw reject("issued by another provider");
    }
    if (!_audiences.isEmpty() && Collections.disjoint(_audiences, strings(answer.get("aud")))) {
      throw reject("not meant for Pinot (aud)");
    }
    Instant expiresAt;
    Object exp = answer.get("exp");
    if (exp instanceof Number) {
      expiresAt = Instant.ofEpochSecond(((Number) exp).longValue());
      if (!expiresAt.isAfter(Instant.ofEpochMilli(nowMs))) {
        throw reject("expired");
      }
    } else {
      // No exp in the answer: trust it for one cache period only
      expiresAt = Instant.ofEpochMilli(nowMs + Math.max(_cache.getTtlMs(), 1000));
    }
    Object user = answer.get(_userClaim);
    if (!(user instanceof String) || ((String) user).trim().isEmpty()) {
      user = answer.get("sub");
    }
    if (!(user instanceof String) || ((String) user).trim().isEmpty()) {
      throw reject("no '" + _userClaim + "' or 'sub' in the introspection answer");
    }
    Set<String> scopes = new LinkedHashSet<>();
    Object scope = answer.get("scope");
    if (scope instanceof String) {
      scopes.addAll(Arrays.asList(((String) scope).trim().split("\\s+")));
      scopes.remove("");
    }
    return new TokenIdentity(((String) user).trim(), strings(answer.get(_groupsClaim)), scopes, expiresAt,
        iss instanceof String ? (String) iss : _issuer, answer);
  }

  private String discover() {
    if (_issuer == null) {
      throw new IllegalArgumentException("Handler " + _name + ": set introspection.url or issuer");
    }
    String base = _issuer.endsWith("/") ? _issuer.substring(0, _issuer.length() - 1) : _issuer;
    try {
      ProviderHttp.Answer answer = _http.get(base + "/.well-known/openid-configuration", Collections.emptyMap());
      if (!answer.isOk()) {
        throw new IOException("discovery answered " + answer._status);
      }
      Object endpoint = JSONObjectUtils.parse(answer._body).get("introspection_endpoint");
      if (!(endpoint instanceof String)) {
        throw new IllegalStateException("Handler " + _name + ": discovery document has no introspection_endpoint");
      }
      return (String) endpoint;
    } catch (IOException | ParseException e) {
      throw new IllegalStateException("Handler " + _name + ": cannot load the discovery document of '" + _issuer
          + "'", e);
    }
  }

  private static Set<String> strings(@Nullable Object value) {
    Set<String> result = new LinkedHashSet<>();
    if (value instanceof String) {
      for (String s : ((String) value).split("[\\s,]+")) {
        if (!s.isEmpty()) {
          result.add(s);
        }
      }
    } else if (value instanceof Collection) {
      for (Object item : (Collection<?>) value) {
        if (item != null) {
          result.add(String.valueOf(item));
        }
      }
    }
    return result;
  }

  private AuthenticationException reject(String reason) {
    return new AuthenticationException("Invalid token (" + _name + "): " + reason, _challenge);
  }

  private AuthenticationException unavailable(String reason, @Nullable Exception cause) {
    return new AuthenticationException("Identity provider unavailable for " + _name + ": " + reason, _challenge,
        cause);
  }

  private static String required(PinotConfiguration config, String key) {
    String value = trimToNull(config.getProperty(key));
    if (value == null) {
      throw new IllegalArgumentException("Missing required introspection handler setting '" + key + "'");
    }
    return value;
  }

  @Nullable
  private static String trimToNull(@Nullable String value) {
    return value == null || value.trim().isEmpty() ? null : value.trim();
  }

  @Override
  public void close() {
    Arrays.fill(_clientSecret, '\0');
  }
}
