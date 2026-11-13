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
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.samples.support.HttpCalls;
import org.apache.pinot.plugin.auth.samples.support.Json;
import org.apache.pinot.plugin.auth.samples.support.JsonMapping;
import org.apache.pinot.plugin.auth.samples.support.Jwts;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Sample token handler for an in-house identity provider that the built-in `jwt` handler cannot express. Copy it,
/// rename the package, and change what your provider does differently; the comments mark the places you are most
/// likely to touch.
///
/// The shape it is written for is common for in-house providers:
/// - the bearer token is a JWT signed with a **shared secret** (HS256 / HS384 / HS512) rather than keys published as
///   JWKS, for example header `{"typ":"JWT","alg":"HS512"}`;
/// - the claims carry the issuer and session details but **no user name and no audience**, for example
///   `{"iss":"identityManager","version":"4.0","tid":"...","sid":"...","iat":...,"exp":...}`;
/// - the provider offers an HTTP API that confirms a token is still valid (not revoked) and/or returns the user and
///   their groups for it.
///
/// What it does for each token, in order (each step optional except the first two):
/// 1. **Recognise.** A compact JWT whose `iss` equals `issuer` is ours; anything else returns `null` so the router
///    tries the next handler. With `accept.opaque=true` a non-JWT token is ours too and is checked with the validation
///    call alone.
/// 2. **Verify locally.** The `alg` must be in `algorithms`; with `hmac.secret.alias` the signature is checked with the
///    secret from Pinot's credential store; `exp` is required and checked with `clock.skew.seconds`, as are `nbf` and
///    `iat` when present; `required.claims` entries (`name` must be present, `name=value` must match) are enforced.
/// 3. **Validate remotely** (`validation.url`). The token is sent to the provider, which answers 2xx for a live token
///    and 400 / 401 / 403 for a bad one; any other answer, a timeout or a connection failure means the provider is
///    unavailable and the request is refused (never let through). With `validation.active.field` the response must
///    also carry `true` in that field (RFC 7662 introspection style).
/// 4. **Look up the user** (`userinfo.url`, then `groups.url`), with the same answer handling.
/// 5. **Map** the user, groups and scopes from the responses (paths `user.field`, `groups.field`, `scopes.field`) or,
///    when a response does not have them, from the token claims (`user.claim`, `groups.claim`, `scopes.claim`).
///
/// At least one of `hmac.secret.alias` and `validation.url` is required, so a token is never accepted on its unverified
/// content. Results are cached by the router per token (see `cache.ttl.seconds` on the handler), so the provider is
/// called once per token per cache period, not once per query.
///
/// Settings (under `pinot.auth.oauth2.handler.<name>.`; secrets only as aliases in the credential store):
///
/// | Setting | Default | Meaning |
/// |---|---|---|
/// | `issuer` | (required) | value of `iss` in the provider's tokens; also used by the router to send them here |
/// | `algorithms` | `HS512` | accepted `alg` values, HMAC only |
/// | `hmac.secret.alias` | | credential-store alias of the shared signing secret |
/// | `hmac.previous.secret.alias` | | alias of the previous secret, also accepted while the provider rotates |
/// | `clock.skew.seconds` | `60` | tolerance for `exp`, `nbf`, `iat` |
/// | `required.claims` | | comma list of `name` or `name=value` |
/// | `accept.opaque` | `false` | also accept non-JWT tokens, validated by `validation.url` only |
/// | `opaque.ttl.seconds` | `300` | lifetime for an opaque token when the response has no expiry |
/// | `validation.url` | | provider API that confirms the token |
/// | `validation.style` | `bearer` | `bearer`: GET with `Authorization: Bearer <token>`; `form`: POST `token=<token>` |
/// | `validation.active.field` | | response field that must be `true` |
/// | `client.id`, `client.secret.alias` | | Pinot's client credentials for the provider API (Basic, `form` style) |
/// | `userinfo.url` | | GET with the bearer token; response used for user / groups / scopes |
/// | `groups.url` | | GET with the bearer token; response used for groups |
/// | `user.field` / `user.claim` | / `sub` | dotted path in the responses / claim in the token |
/// | `groups.field` / `groups.claim` | / `groups` | same for groups (array or comma / space separated string) |
/// | `scopes.field` / `scopes.claim` | / `scope` | same for scopes |
/// | `expires.field` | | response field with the expiry in epoch seconds (opaque tokens) |
/// | `http.timeout.ms` | `3000` | connect and request timeout per provider call |
///
/// Thread-safe after [#init]: all state is final configuration plus a thread-safe HTTP client.
public class CustomIdpTokenHandler implements OAuthTokenHandler {
  private static final Logger LOGGER = LoggerFactory.getLogger(CustomIdpTokenHandler.class);

  private String _name;
  private String _challenge;
  private Clock _clock;
  private HttpCalls _http;

  private String _issuer;
  private Set<String> _algorithms;
  @Nullable
  private byte[] _secret;
  @Nullable
  private byte[] _previousSecret;
  private long _skewSeconds;
  private Map<String, String> _requiredClaims;
  private boolean _acceptOpaque;
  private long _opaqueTtlSeconds;

  @Nullable
  private String _validationUrl;
  private boolean _formStyle;
  @Nullable
  private String _activeField;
  @Nullable
  private String _clientAuthorization;
  @Nullable
  private String _userInfoUrl;
  @Nullable
  private String _groupsUrl;

  @Nullable
  private String _userField;
  private String _userClaim;
  @Nullable
  private String _groupsField;
  private String _groupsClaim;
  @Nullable
  private String _scopesField;
  private String _scopesClaim;
  @Nullable
  private String _expiresField;

  @Override
  public void init(HandlerContext context) {
    PinotConfiguration config = context.getConfig();
    _name = context.getName();
    _clock = context.getClock();
    _challenge = AuthenticationException.challengeFor(AuthMethod.OAUTH2) + ", error=\"invalid_token\"";
    _http = new HttpCalls(Duration.ofMillis(config.getProperty("http.timeout.ms", 3000L)));

    _issuer = required(config, "issuer");
    _algorithms = csv(config.getProperty("algorithms", "HS512"));
    for (String algorithm : _algorithms) {
      // Only HMAC here; tokens signed with published RSA / EC keys belong to the built-in jwt handler
      Jwts.macName(algorithm);
    }
    String secretAlias = optional(config, "hmac.secret.alias");
    if (secretAlias != null) {
      // The secret never sits in configuration: the management tooling writes it to the credential store
      char[] secret = context.getSecretResolver().resolve(secretAlias);
      _secret = toBytes(secret);
      String previousAlias = optional(config, "hmac.previous.secret.alias");
      if (previousAlias != null) {
        // Accept tokens signed with the previous secret too, so the provider and Pinot need not switch at one instant
        _previousSecret = toBytes(context.getSecretResolver().resolve(previousAlias));
      }
    }
    _skewSeconds = config.getProperty("clock.skew.seconds", 60L);
    _requiredClaims = parseRequiredClaims(config.getProperty("required.claims", ""));
    _acceptOpaque = config.getProperty("accept.opaque", false);
    _opaqueTtlSeconds = config.getProperty("opaque.ttl.seconds", 300L);

    _validationUrl = optional(config, "validation.url");
    String style = config.getProperty("validation.style", "bearer").trim();
    if (!style.equals("bearer") && !style.equals("form")) {
      throw new IllegalArgumentException("Handler " + _name + ": validation.style must be bearer or form");
    }
    _formStyle = style.equals("form");
    _activeField = optional(config, "validation.active.field");
    String clientId = optional(config, "client.id");
    if (clientId != null) {
      String clientSecretAlias = required(config, "client.secret.alias");
      char[] clientSecret = context.getSecretResolver().resolve(clientSecretAlias);
      _clientAuthorization = HttpCalls.basic(clientId, clientSecret);
      Arrays.fill(clientSecret, '\0');
    }
    _userInfoUrl = optional(config, "userinfo.url");
    _groupsUrl = optional(config, "groups.url");

    _userField = optional(config, "user.field");
    _userClaim = config.getProperty("user.claim", "sub").trim();
    _groupsField = optional(config, "groups.field");
    _groupsClaim = config.getProperty("groups.claim", "groups").trim();
    _scopesField = optional(config, "scopes.field");
    _scopesClaim = config.getProperty("scopes.claim", "scope").trim();
    _expiresField = optional(config, "expires.field");

    // Refuse a configuration that would accept a token on its unverified content
    if (_secret == null && _validationUrl == null) {
      throw new IllegalArgumentException("Handler " + _name + ": set hmac.secret.alias, validation.url or both");
    }
    if (_acceptOpaque && _validationUrl == null) {
      throw new IllegalArgumentException("Handler " + _name + ": accept.opaque needs validation.url");
    }
    LOGGER.info("Custom token handler {} ready: issuer={}, local signature check={}, validation call={}, user-info "
        + "call={}, groups call={}", _name, _issuer, _secret != null, _validationUrl != null, _userInfoUrl != null,
        _groupsUrl != null);
  }

  @Nullable
  @Override
  public TokenIdentity validate(String token) {
    Jwts.Parsed jwt = Jwts.parse(token);
    Instant now = _clock.instant();

    // Step 1: recognise. Returning null hands the token to the next handler; throwing would end the request.
    Map<String, Object> claims;
    Instant expiresAt;
    if (jwt != null) {
      if (!_issuer.equals(JsonMapping.getString(jwt.getClaims(), "iss"))) {
        return null;
      }
      claims = jwt.getClaims();
      // Step 2: local checks on our own tokens
      expiresAt = checkJwt(jwt, now);
    } else if (_acceptOpaque) {
      claims = Collections.emptyMap();
      expiresAt = null;
    } else {
      return null;
    }

    // Step 3: ask the provider whether the token is still valid (catches revoked sessions)
    List<Map<String, Object>> responses = new ArrayList<>();
    if (_validationUrl != null) {
      Map<String, Object> validation = callValidation(token);
      if (_activeField != null && !Boolean.TRUE.equals(JsonMapping.get(validation, _activeField))) {
        throw reject("the identity provider reports the token as not active");
      }
      responses.add(validation);
    }

    // Step 4: who is it? Change these calls if your provider looks users up by a claim (e.g. sid) instead of the token
    if (_userInfoUrl != null) {
      responses.add(callWithBearer(_userInfoUrl, token, "user-info"));
    }
    Map<String, Object> groupsResponse = _groupsUrl != null ? callWithBearer(_groupsUrl, token, "groups") : null;

    // Step 5: map
    String user = firstString(responses, _userField);
    if (user == null) {
      user = JsonMapping.getString(claims, _userClaim);
    }
    if (user == null || user.trim().isEmpty()) {
      throw reject("no user in the identity provider's answer or the token");
    }
    Set<String> groups = new LinkedHashSet<>();
    if (groupsResponse != null && _groupsField != null) {
      groups.addAll(JsonMapping.getStrings(groupsResponse, _groupsField));
    }
    groups.addAll(allStrings(responses, _groupsField));
    groups.addAll(JsonMapping.getStrings(claims, _groupsClaim));
    Set<String> scopes = new LinkedHashSet<>(allStrings(responses, _scopesField));
    scopes.addAll(JsonMapping.getStrings(claims, _scopesClaim));

    if (expiresAt == null) {
      expiresAt = opaqueExpiry(responses, now);
    }
    // Attributes go to audit and identity mapping: claims and the mapped user, never the token itself
    Map<String, Object> attributes = new LinkedHashMap<>(claims);
    attributes.put("handler", _name);
    return new TokenIdentity(user.trim(), groups, scopes, expiresAt, _issuer, attributes);
  }

  /// Signature, algorithm, time and required-claim checks on a token of our issuer.
  ///
  /// @return the token expiry
  private Instant checkJwt(Jwts.Parsed jwt, Instant now) {
    String algorithm = jwt.getAlgorithm();
    if (algorithm == null || !_algorithms.contains(algorithm)) {
      // Also stops "alg":"none" and algorithm-confusion tokens
      throw reject("algorithm " + algorithm + " is not accepted");
    }
    if (_secret != null && !Jwts.verifyHmac(jwt, _secret) && (_previousSecret == null || !Jwts.verifyHmac(jwt,
        _previousSecret))) {
      throw reject("bad signature");
    }
    Map<String, Object> claims = jwt.getClaims();
    Long exp = JsonMapping.getLong(claims, "exp");
    if (exp == null) {
      throw reject("no expiry (exp)");
    }
    Instant expiresAt = Instant.ofEpochSecond(exp);
    if (now.isAfter(expiresAt.plusSeconds(_skewSeconds))) {
      throw reject("expired");
    }
    Long nbf = JsonMapping.getLong(claims, "nbf");
    if (nbf != null && now.plusSeconds(_skewSeconds).isBefore(Instant.ofEpochSecond(nbf))) {
      throw reject("not valid yet (nbf)");
    }
    Long iat = JsonMapping.getLong(claims, "iat");
    if (iat != null && now.plusSeconds(_skewSeconds).isBefore(Instant.ofEpochSecond(iat))) {
      throw reject("issued in the future (iat)");
    }
    for (Map.Entry<String, String> required : _requiredClaims.entrySet()) {
      String value = JsonMapping.getString(claims, required.getKey());
      if (value == null || (!required.getValue().isEmpty() && !required.getValue().equals(value))) {
        throw reject("claim '" + required.getKey() + "' is missing or does not have the required value");
      }
    }
    return expiresAt;
  }

  private Map<String, Object> callValidation(String token) {
    Map<String, String> headers = new LinkedHashMap<>();
    HttpCalls.Response response;
    try {
      if (_formStyle) {
        // RFC 7662 style: the token in the body, Pinot's own client credentials in the header
        if (_clientAuthorization != null) {
          headers.put("Authorization", _clientAuthorization);
        }
        response = _http.postForm(_validationUrl, Collections.singletonMap("token", token), headers);
      } else {
        headers.put("Authorization", "Bearer " + token);
        response = _http.get(_validationUrl, headers);
      }
    } catch (IOException | RuntimeException e) {
      throw unavailable("validation", e);
    }
    return readAnswer(response, "validation");
  }

  private Map<String, Object> callWithBearer(String url, String token, String call) {
    HttpCalls.Response response;
    try {
      response = _http.get(url, Collections.singletonMap("Authorization", "Bearer " + token));
    } catch (IOException | RuntimeException e) {
      throw unavailable(call, e);
    }
    return readAnswer(response, call);
  }

  /// 2xx with a JSON object: the answer. 400 / 401 / 403: the provider rejects the token. Anything else: the provider
  /// is unavailable. Adjust here if your provider signals a bad token differently (e.g. 200 with an error field).
  private Map<String, Object> readAnswer(HttpCalls.Response response, String call) {
    int status = response.getStatus();
    if (status == 400 || status == 401 || status == 403) {
      throw reject("rejected by the identity provider (" + call + " call answered " + status + ")");
    }
    if (!response.isOk()) {
      throw new AuthenticationException("Identity provider unavailable for " + _name + ": " + call + " call answered "
          + status, _challenge);
    }
    String body = response.getBody().trim();
    if (body.isEmpty()) {
      return Collections.emptyMap();
    }
    try {
      return Json.parseObject(body);
    } catch (IllegalArgumentException e) {
      throw new AuthenticationException("Identity provider unavailable for " + _name + ": " + call + " call did not "
          + "answer a JSON object", _challenge);
    }
  }

  private Instant opaqueExpiry(List<Map<String, Object>> responses, Instant now) {
    if (_expiresField != null) {
      for (Map<String, Object> response : responses) {
        Long epochSeconds = JsonMapping.getLong(response, _expiresField);
        if (epochSeconds != null) {
          Instant expiresAt = Instant.ofEpochSecond(epochSeconds);
          if (now.isAfter(expiresAt.plusSeconds(_skewSeconds))) {
            throw reject("expired");
          }
          return expiresAt;
        }
      }
    }
    return now.plusSeconds(_opaqueTtlSeconds);
  }

  @Nullable
  private static String firstString(List<Map<String, Object>> responses, @Nullable String path) {
    if (path == null) {
      return null;
    }
    for (Map<String, Object> response : responses) {
      String value = JsonMapping.getString(response, path);
      if (value != null) {
        return value;
      }
    }
    return null;
  }

  private static Set<String> allStrings(List<Map<String, Object>> responses, @Nullable String path) {
    Set<String> values = new LinkedHashSet<>();
    if (path != null) {
      for (Map<String, Object> response : responses) {
        values.addAll(JsonMapping.getStrings(response, path));
      }
    }
    return values;
  }

  private byte[] toBytes(char[] secret) {
    if (secret.length == 0) {
      throw new IllegalArgumentException("Handler " + _name + ": a configured secret is empty");
    }
    byte[] bytes = new String(secret).getBytes(StandardCharsets.UTF_8);
    Arrays.fill(secret, '\0');
    return bytes;
  }

  private AuthenticationException reject(String reason) {
    // The reason is logged and returned; it must never contain the token
    return new AuthenticationException("Invalid token (" + _name + "): " + reason, _challenge);
  }

  private AuthenticationException unavailable(String call, Exception e) {
    LOGGER.warn("Handler {}: {} call to the identity provider failed: {}", _name, call, e.toString());
    return new AuthenticationException("Identity provider unavailable for " + _name + ": " + call + " call failed",
        _challenge, e);
  }

  @Nullable
  static String optional(PinotConfiguration config, String key) {
    String value = config.getProperty(key);
    return value == null || value.trim().isEmpty() ? null : value.trim();
  }

  static String required(PinotConfiguration config, String key) {
    String value = optional(config, key);
    if (value == null) {
      throw new IllegalArgumentException("Missing required handler setting '" + key + "'");
    }
    return value;
  }

  static Set<String> csv(String value) {
    Set<String> parts = new LinkedHashSet<>();
    for (String part : value.split(",")) {
      if (!part.trim().isEmpty()) {
        parts.add(part.trim());
      }
    }
    return parts;
  }

  /// `name` (must be present) or `name=value` (must match), comma separated.
  static Map<String, String> parseRequiredClaims(String value) {
    Map<String, String> claims = new LinkedHashMap<>();
    for (String entry : csv(value)) {
      int eq = entry.indexOf('=');
      if (eq == 0) {
        throw new IllegalArgumentException("required.claims entries must be name or name=value, got '" + entry + "'");
      }
      if (eq < 0) {
        claims.put(entry, "");
      } else {
        claims.put(entry.substring(0, eq).trim(), entry.substring(eq + 1).trim());
      }
    }
    return claims;
  }
}
