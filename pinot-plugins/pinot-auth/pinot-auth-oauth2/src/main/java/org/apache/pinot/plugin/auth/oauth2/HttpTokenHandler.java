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

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Validates tokens by calling a provider API described entirely in configuration, for providers that are neither a
/// standard JWT issuer nor an RFC 7662 introspection endpoint. No code: a request template, a success condition and a
/// JSON mapping.
///
/// The call (`request.*`):
/// - `request.url` (fixed host: placeholders are encoded as URL components, so a token cannot change the target),
///   `request.method` `GET` (default) or `POST`, `request.header.<id>` = `<Name>: <value>`, `request.body`,
///   `request.content.type`
///   (default `application/json`; `application/x-www-form-urlencoded` encodes body values as form fields)
/// - placeholders: `${token}`, `${client.id}`, `${now.epochSeconds}`, `${now.epochMillis}`, `${secret:<alias>}`
///   (credential store, resolved at start)
/// - mutual TLS: `tls.keystore.path` + `tls.keystore.password.alias`, `tls.truststore.path` +
///   `tls.truststore.password.alias`, `tls.store.type` (default PKCS12)
///
/// The answer:
/// - `success.status` (default `200`): status codes of an answer that may accept the token; `reject.status`
///   (default `400,401,403`): the provider rejects the token; anything else, a timeout or a connection failure: the
///   provider is unavailable and the request is refused
/// - `success.condition`: `<JsonPath>` (must be `true`), `<JsonPath> == <value>` or `<JsonPath> != <value>`; false
///   rejects the token
/// - `map.user` (JsonPath, required), `map.groups`, `map.scopes` (arrays, or strings split by `map.groups.split` /
///   `map.scopes.split`, default commas and spaces), `map.expiresAt` with `map.expiresAt.format` `epochSeconds`
///   (default), `epochMillis`, `iso8601` or `ttlSeconds`, `map.attribute.<name>`
/// - `map.user.transform` / `map.groups.transform`: steps separated by `;`: `lower`, `upper`, `strip-prefix:<p>`,
///   `strip-suffix:<s>`, `replace:<regex>=><replacement>`
/// - optional enrich call `enrich.url` / `.method` / `.header.<id>` / `.body` / `.content.type` with the extra
///   placeholder `${user}`, mapped by `enrich.map.groups` and `enrich.map.scopes`
///
/// Robustness: `http.timeout.ms` (default 3000), `retries` (default 1, only after a connection failure or a 5xx),
/// answers above `http.size.limit.bytes` (65536) refused, circuit breaker (`breaker.failures` consecutive provider
/// failures, default 5, open the breaker for `breaker.open.seconds`, default 30, during which tokens are refused
/// without calling), and the same answer cache as the introspection handler (`cache.ttl.seconds`,
/// `negative.cache.seconds`, `cache.max.entries`).
///
/// Routing: `issuer` routes JWTs of that issuer here; opaque tokens also come here unless `opaque.tokens=false`.
/// Thread-safe after [#init].
final class HttpTokenHandler implements OAuthTokenHandler {
  static final String TYPE = "http";
  private static final Logger LOGGER = LoggerFactory.getLogger(HttpTokenHandler.class);
  private static final Configuration JSON_PATH =
      Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS);
  private static final Set<String> MAIN_PLACEHOLDERS =
      RequestTemplate.names("token", "client.id", "now.epochSeconds", "now.epochMillis");
  private static final Set<String> ENRICH_PLACEHOLDERS =
      RequestTemplate.names("token", "client.id", "now.epochSeconds", "now.epochMillis", "user");

  private String _name;
  private String _challenge;
  private Clock _clock;
  private ProviderHttp _http;
  @Nullable
  private String _issuer;
  private String _clientId;
  private Call _call;
  @Nullable
  private Call _enrich;
  private Map<String, String> _secrets;
  private Set<Integer> _successStatus;
  private Set<Integer> _rejectStatus;
  @Nullable
  private Condition _condition;
  private JsonPath _userPath;
  private List<Transform> _userTransforms;
  @Nullable
  private JsonPath _groupsPath;
  private Pattern _groupsSplit;
  private List<Transform> _groupsTransforms;
  @Nullable
  private JsonPath _scopesPath;
  private Pattern _scopesSplit;
  @Nullable
  private JsonPath _expiresPath;
  private String _expiresFormat;
  private Map<String, JsonPath> _attributes;
  @Nullable
  private JsonPath _enrichGroupsPath;
  @Nullable
  private JsonPath _enrichScopesPath;
  private int _retries;
  private int _breakerFailures;
  private long _breakerOpenMs;
  private final AtomicInteger _consecutiveFailures = new AtomicInteger();
  private final AtomicLong _breakerOpenUntilMs = new AtomicLong();
  private TokenResultCache _cache;

  /// One configured provider call; also used by [HttpTokenSource].
  static final class Call {
    final RequestTemplate _url;
    final String _method;
    final Map<String, RequestTemplate> _headers = new LinkedHashMap<>();
    @Nullable
    final RequestTemplate _body;
    final String _contentType;

    Call(PinotConfiguration config, String prefix, Set<String> allowed, String handler) {
      String url = config.getProperty(prefix + ".url");
      if (url == null || url.trim().isEmpty()) {
        throw new IllegalArgumentException("Handler " + handler + ": " + prefix + ".url is required");
      }
      _url = new RequestTemplate(url.trim(), RequestTemplate.Encoding.URL, allowed, "Handler " + handler);
      _method = config.getProperty(prefix + ".method", "GET").trim().toUpperCase(Locale.ROOT);
      if (!_method.equals("GET") && !_method.equals("POST")) {
        throw new IllegalArgumentException("Handler " + handler + ": " + prefix + ".method must be GET or POST");
      }
      // The header name is in the value (`<Name>: <template>`): configuration keys are normalized, so they cannot
      // carry a header name's spelling
      PinotConfiguration headers = config.subset(prefix + ".header");
      for (String key : headers.getKeys()) {
        String header = headers.getProperty(key);
        int colon = header.indexOf(':');
        if (colon <= 0) {
          throw new IllegalArgumentException("Handler " + handler + ": " + prefix + ".header." + key
              + " must be '<Name>: <value>'");
        }
        _headers.put(header.substring(0, colon).trim(), new RequestTemplate(header.substring(colon + 1).trim(),
            RequestTemplate.Encoding.HEADER, allowed, "Handler " + handler));
      }
      _contentType = config.getProperty(prefix + ".content.type", "application/json").trim();
      String body = config.getProperty(prefix + ".body");
      RequestTemplate.Encoding bodyEncoding = _contentType.startsWith("application/x-www-form-urlencoded")
          ? RequestTemplate.Encoding.FORM
          : _contentType.contains("json") ? RequestTemplate.Encoding.JSON : RequestTemplate.Encoding.TEXT;
      _body = body == null || body.isEmpty() ? null
          : new RequestTemplate(body, bodyEncoding, allowed, "Handler " + handler);
    }

    List<String> secretAliases() {
      List<String> aliases = new ArrayList<>(_url.secretAliases());
      _headers.values().forEach(h -> aliases.addAll(h.secretAliases()));
      if (_body != null) {
        aliases.addAll(_body.secretAliases());
      }
      return aliases;
    }

    HttpRequest build(Map<String, String> values, Duration timeout) {
      HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(_url.render(values))).timeout(timeout)
          .header("Accept", "application/json");
      _headers.forEach((name, value) -> builder.header(name, value.render(values)));
      if (_method.equals("POST")) {
        builder.header("Content-Type", _contentType)
            .POST(HttpRequest.BodyPublishers.ofString(_body == null ? "" : _body.render(values)));
      } else {
        builder.GET();
      }
      return builder.build();
    }
  }

  /// `success.condition`: a JsonPath that must be true, or compared with a literal.
  private static final class Condition {
    final JsonPath _path;
    @Nullable
    final String _operator;
    @Nullable
    final String _value;

    Condition(String expression) {
      String[] parts = expression.trim().split("\\s+(==|!=)\\s+", 2);
      _path = JsonPath.compile(parts[0].trim());
      if (parts.length == 2) {
        _operator = expression.contains("!=") ? "!=" : "==";
        String value = parts[1].trim();
        _value = value.length() >= 2 && (value.startsWith("'") && value.endsWith("'")
            || value.startsWith("\"") && value.endsWith("\"")) ? value.substring(1, value.length() - 1) : value;
      } else {
        _operator = null;
        _value = null;
      }
    }

    boolean test(DocumentContext document) {
      Object actual = document.read(_path);
      if (_operator == null) {
        return Boolean.TRUE.equals(actual) || "true".equals(actual);
      }
      boolean equal = actual != null && String.valueOf(actual).equals(_value);
      return _operator.equals("==") == equal;
    }
  }

  /// One step of a user / group name transform.
  private static final class Transform {
    final String _kind;
    final String _argument;
    @Nullable
    final Pattern _pattern;
    @Nullable
    final String _replacement;

    Transform(String step) {
      int colon = step.indexOf(':');
      _kind = (colon < 0 ? step : step.substring(0, colon)).trim();
      _argument = colon < 0 ? "" : step.substring(colon + 1);
      if (_kind.equals("replace")) {
        int arrow = _argument.indexOf("=>");
        if (arrow < 0) {
          throw new IllegalArgumentException("replace transform must be replace:<regex>=><replacement>");
        }
        _pattern = Pattern.compile(_argument.substring(0, arrow));
        _replacement = _argument.substring(arrow + 2);
      } else if (_kind.equals("lower") || _kind.equals("upper") || _kind.equals("strip-prefix")
          || _kind.equals("strip-suffix")) {
        _pattern = null;
        _replacement = null;
      } else {
        throw new IllegalArgumentException("Unknown transform '" + _kind + "'");
      }
    }

    String apply(String value) {
      switch (_kind) {
        case "lower":
          return value.toLowerCase(Locale.ROOT);
        case "upper":
          return value.toUpperCase(Locale.ROOT);
        case "strip-prefix":
          return value.startsWith(_argument) ? value.substring(_argument.length()) : value;
        case "strip-suffix":
          return value.endsWith(_argument) ? value.substring(0, value.length() - _argument.length()) : value;
        default:
          return _pattern.matcher(value).replaceAll(_replacement);
      }
    }

    static List<Transform> parse(@Nullable String steps) {
      List<Transform> transforms = new ArrayList<>();
      if (steps != null) {
        for (String step : steps.split(";")) {
          if (!step.trim().isEmpty()) {
            transforms.add(new Transform(step.trim()));
          }
        }
      }
      return transforms;
    }

    static String applyAll(List<Transform> transforms, String value) {
      for (Transform transform : transforms) {
        value = transform.apply(value);
      }
      return value;
    }
  }

  @Override
  public void init(HandlerContext context) {
    PinotConfiguration config = context.getConfig();
    _name = context.getName();
    _clock = context.getClock();
    _challenge = AuthenticationException.challengeFor(AuthMethod.OAUTH2) + ", error=\"invalid_token\"";
    _http = new ProviderHttp(config.getProperty("http.timeout.ms", 3000L),
        config.getProperty("http.size.limit.bytes", ProviderHttp.DEFAULT_MAX_RESPONSE_BYTES),
        sslContext(config, context.getSecretResolver()));
    _issuer = trimToNull(config.getProperty("issuer"));
    _clientId = config.getProperty("client.id", "").trim();
    _call = new Call(config, "request", MAIN_PLACEHOLDERS, _name);
    _enrich = trimToNull(config.getProperty("enrich.url")) == null ? null
        : new Call(config, "enrich", ENRICH_PLACEHOLDERS, _name);
    _secrets = new HashMap<>();
    List<String> aliases = new ArrayList<>(_call.secretAliases());
    if (_enrich != null) {
      aliases.addAll(_enrich.secretAliases());
    }
    for (String alias : aliases) {
      _secrets.put("secret:" + alias, new String(context.getSecretResolver().resolve(alias)));
    }
    _successStatus = statuses(config.getProperty("success.status", "200"));
    _rejectStatus = statuses(config.getProperty("reject.status", "400,401,403"));
    String condition = trimToNull(config.getProperty("success.condition"));
    _condition = condition == null ? null : new Condition(condition);
    String userPath = trimToNull(config.getProperty("map.user"));
    if (userPath == null) {
      throw new IllegalArgumentException("Handler " + _name + ": map.user is required");
    }
    _userPath = JsonPath.compile(userPath);
    _userTransforms = Transform.parse(config.getProperty("map.user.transform"));
    _groupsPath = compile(config.getProperty("map.groups"));
    _groupsSplit = Pattern.compile(config.getProperty("map.groups.split", "[,\\s]+"));
    _groupsTransforms = Transform.parse(config.getProperty("map.groups.transform"));
    _scopesPath = compile(config.getProperty("map.scopes"));
    _scopesSplit = Pattern.compile(config.getProperty("map.scopes.split", "[,\\s]+"));
    _expiresPath = compile(config.getProperty("map.expiresAt"));
    _expiresFormat = config.getProperty("map.expiresAt.format", "epochSeconds").trim();
    if (!Set.of("epochSeconds", "epochMillis", "iso8601", "ttlSeconds").contains(_expiresFormat)) {
      throw new IllegalArgumentException("Handler " + _name + ": unknown map.expiresAt.format " + _expiresFormat);
    }
    _attributes = new LinkedHashMap<>();
    PinotConfiguration attributes = config.subset("map.attribute");
    for (String key : attributes.getKeys()) {
      _attributes.put(key, JsonPath.compile(attributes.getProperty(key)));
    }
    _enrichGroupsPath = compile(config.getProperty("enrich.map.groups"));
    _enrichScopesPath = compile(config.getProperty("enrich.map.scopes"));
    _retries = config.getProperty("retries", 1);
    _breakerFailures = config.getProperty("breaker.failures", 5);
    _breakerOpenMs = config.getProperty("breaker.open.seconds", 30L) * 1000;
    _cache = new TokenResultCache(config);
    LOGGER.info("Http token handler {} ready: {} {}, enrich call={}, issuer={}", _name, _call._method,
        hostOf(config.getProperty("request.url")), _enrich != null, _issuer);
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
        throw reject("rejected by the identity provider (cached)");
      }
      return cached._identity;
    }
    Map<String, String> values = new HashMap<>(_secrets);
    values.put("token", token);
    values.put("client.id", _clientId);
    values.put("now.epochSeconds", String.valueOf(nowMs / 1000));
    values.put("now.epochMillis", String.valueOf(nowMs));

    ProviderHttp.Answer answer = call(_call, values, "validation");
    if (_rejectStatus.contains(answer._status)) {
      _cache.putRejected(key, nowMs);
      throw reject("rejected by the identity provider (answered " + answer._status + ")");
    }
    if (!_successStatus.contains(answer._status)) {
      failure();
      throw unavailable("validation call answered " + answer._status, null);
    }
    DocumentContext document = parse(answer, "validation");
    succeeded();
    if (_condition != null && !_condition.test(document)) {
      _cache.putRejected(key, nowMs);
      throw reject("the identity provider's answer does not meet success.condition");
    }
    Object rawUser = document.read(_userPath);
    if (!(rawUser instanceof String || rawUser instanceof Number) || String.valueOf(rawUser).trim().isEmpty()) {
      throw reject("no user at map.user in the identity provider's answer");
    }
    String user = Transform.applyAll(_userTransforms, String.valueOf(rawUser).trim());
    Set<String> groups = strings(_groupsPath == null ? null : document.read(_groupsPath), _groupsSplit);
    Set<String> scopes = strings(_scopesPath == null ? null : document.read(_scopesPath), _scopesSplit);
    Instant expiresAt = expiry(_expiresPath == null ? null : document.read(_expiresPath), nowMs);
    if (!expiresAt.isAfter(Instant.ofEpochMilli(nowMs))) {
      throw reject("expired");
    }
    Map<String, Object> attributes = new LinkedHashMap<>();
    _attributes.forEach((name, path) -> {
      Object value = document.read(path);
      if (value != null) {
        attributes.put(name, value);
      }
    });

    if (_enrich != null) {
      values.put("user", user);
      ProviderHttp.Answer enrichAnswer = call(_enrich, values, "enrich");
      if (!enrichAnswer.isOk()) {
        failure();
        throw unavailable("enrich call answered " + enrichAnswer._status, null);
      }
      DocumentContext enriched = parse(enrichAnswer, "enrich");
      succeeded();
      if (_enrichGroupsPath != null) {
        groups.addAll(strings(enriched.read(_enrichGroupsPath), _groupsSplit));
      }
      if (_enrichScopesPath != null) {
        scopes.addAll(strings(enriched.read(_enrichScopesPath), _scopesSplit));
      }
    }
    Set<String> mappedGroups = new LinkedHashSet<>();
    for (String group : groups) {
      mappedGroups.add(Transform.applyAll(_groupsTransforms, group));
    }
    TokenIdentity identity = new TokenIdentity(user, mappedGroups, scopes, expiresAt, _issuer, attributes);
    _cache.putAccepted(key, identity, nowMs);
    return identity;
  }

  /// Sends a call with the breaker and retry rules; never returns for a provider failure.
  private ProviderHttp.Answer call(Call call, Map<String, String> values, String what) {
    long nowMs = _clock.millis();
    if (_breakerOpenUntilMs.get() > nowMs) {
      throw unavailable("circuit breaker open after repeated provider failures", null);
    }
    HttpRequest request;
    try {
      request = call.build(values, Duration.ofMillis(_http.getTimeoutMs()));
    } catch (IllegalArgumentException e) {
      throw reject("token cannot be placed in the " + what + " request");
    }
    IOException last = null;
    for (int attempt = 0; attempt <= _retries; attempt++) {
      try {
        ProviderHttp.Answer answer = _http.send(request);
        if (answer._status >= 500 && attempt < _retries) {
          continue;
        }
        return answer;
      } catch (IOException e) {
        last = e;
      }
    }
    failure();
    LOGGER.warn("Handler {}: {} call failed: {}", _name, what, last.toString());
    throw unavailable(what + " call failed", last);
  }

  private DocumentContext parse(ProviderHttp.Answer answer, String what) {
    try {
      Object json = JSON_PATH.jsonProvider().parse(answer._body);
      // The default parser is lenient (a bare word parses as a string): only an object or array is an answer
      if (!(json instanceof Map) && !(json instanceof List)) {
        throw new IllegalArgumentException("not a JSON object or array");
      }
      return JsonPath.using(JSON_PATH).parse(json);
    } catch (RuntimeException e) {
      failure();
      throw unavailable(what + " answer is not JSON", null);
    }
  }

  private void failure() {
    if (_consecutiveFailures.incrementAndGet() >= _breakerFailures) {
      _breakerOpenUntilMs.set(_clock.millis() + _breakerOpenMs);
      _consecutiveFailures.set(0);
      LOGGER.warn("Handler {}: {} consecutive provider failures, refusing tokens for {} s without calling", _name,
          _breakerFailures, _breakerOpenMs / 1000);
    }
  }

  private void succeeded() {
    _consecutiveFailures.set(0);
  }

  private Instant expiry(@Nullable Object value, long nowMs) {
    if (value == null) {
      return Instant.ofEpochMilli(nowMs + Math.max(_cache.getTtlMs(), 1000));
    }
    try {
      switch (_expiresFormat) {
        case "epochMillis":
          return Instant.ofEpochMilli(Long.parseLong(String.valueOf(value)));
        case "iso8601":
          return Instant.parse(String.valueOf(value));
        case "ttlSeconds":
          return Instant.ofEpochMilli(nowMs).plusSeconds(Long.parseLong(String.valueOf(value)));
        default:
          return Instant.ofEpochSecond(Long.parseLong(String.valueOf(value)));
      }
    } catch (NumberFormatException | DateTimeParseException e) {
      throw reject("expiry at map.expiresAt is not " + _expiresFormat);
    }
  }

  private static Set<String> strings(@Nullable Object value, Pattern split) {
    Set<String> result = new LinkedHashSet<>();
    if (value instanceof Collection) {
      for (Object item : (Collection<?>) value) {
        if (item != null && !String.valueOf(item).trim().isEmpty()) {
          result.add(String.valueOf(item).trim());
        }
      }
    } else if (value != null) {
      for (String part : split.split(String.valueOf(value))) {
        if (!part.trim().isEmpty()) {
          result.add(part.trim());
        }
      }
    }
    return result;
  }

  @Nullable
  private static SSLContext sslContext(PinotConfiguration config, SecretResolver secrets) {
    String keyStore = trimToNull(config.getProperty("tls.keystore.path"));
    String trustStore = trimToNull(config.getProperty("tls.truststore.path"));
    if (keyStore == null && trustStore == null) {
      return null;
    }
    String type = config.getProperty("tls.store.type", "PKCS12");
    try {
      KeyManagerFactory keyManagers = null;
      if (keyStore != null) {
        char[] password = secrets.resolve(config.getProperty("tls.keystore.password.alias", ""));
        keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(load(keyStore, type, password), password);
      }
      TrustManagerFactory trustManagers = null;
      if (trustStore != null) {
        char[] password = secrets.resolve(config.getProperty("tls.truststore.password.alias", ""));
        trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(load(trustStore, type, password));
      }
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(keyManagers == null ? null : keyManagers.getKeyManagers(),
          trustManagers == null ? null : trustManagers.getTrustManagers(), null);
      return context;
    } catch (GeneralSecurityException | IOException e) {
      throw new IllegalStateException("Cannot set up TLS to the identity provider", e);
    }
  }

  private static KeyStore load(String path, String type, char[] password)
      throws GeneralSecurityException, IOException {
    KeyStore store = KeyStore.getInstance(type);
    try (InputStream in = new FileInputStream(new File(path))) {
      store.load(in, password);
    }
    return store;
  }

  private static Set<Integer> statuses(String value) {
    Set<Integer> result = new LinkedHashSet<>();
    for (String part : JwtTokenHandler.csv(value)) {
      result.add(Integer.parseInt(part));
    }
    return result;
  }

  @Nullable
  private static JsonPath compile(@Nullable String path) {
    String trimmed = trimToNull(path);
    return trimmed == null ? null : JsonPath.compile(trimmed);
  }

  private static String hostOf(String url) {
    try {
      return URI.create(url.trim().replaceAll("\\$\\{[^}]*}", "x")).getHost();
    } catch (IllegalArgumentException e) {
      return "?";
    }
  }

  @Nullable
  private static String trimToNull(@Nullable String value) {
    return value == null || value.trim().isEmpty() ? null : value.trim();
  }

  private AuthenticationException reject(String reason) {
    return new AuthenticationException("Invalid token (" + _name + "): " + reason, _challenge);
  }

  private AuthenticationException unavailable(String reason, @Nullable Exception cause) {
    return new AuthenticationException("Identity provider unavailable for " + _name + ": " + reason, _challenge,
        cause);
  }
}
