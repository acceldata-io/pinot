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
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AccessToken;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenSource;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Tokens for Pinot's own calls from a provider endpoint described in configuration, for providers whose token
/// endpoint is not a standard OAuth 2.0 one. The same request template as the `http` token handler:
/// `request.url`, `request.method` (default `POST`), `request.header.<id>=<Name>: <value>`, `request.body`,
/// `request.content.type`, placeholders `${client.id}`, `${now.epochSeconds}`, `${now.epochMillis}`,
/// `${secret:<alias>}`. The answer must be 2xx JSON; `map.token` (JsonPath, required), and the lifetime from
/// `map.expiresIn` (seconds) or `map.expiresAt` with `map.expiresAt.format` (`epochSeconds`, `epochMillis`,
/// `iso8601`), else `default.ttl.seconds` (300). Thread-safe after [#init].
public class HttpTokenSource implements OAuthTokenSource {
  public static final String TYPE = "http";
  private static final Configuration JSON_PATH =
      Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS);
  private static final Set<String> PLACEHOLDERS =
      RequestTemplate.names("client.id", "now.epochSeconds", "now.epochMillis");

  private String _name;
  private HandlerContext _context;
  private ProviderHttp _http;
  private HttpTokenHandler.Call _call;
  private Map<String, String> _values;
  private JsonPath _tokenPath;
  @Nullable
  private JsonPath _expiresInPath;
  @Nullable
  private JsonPath _expiresAtPath;
  private String _expiresAtFormat;
  private long _defaultTtlSeconds;

  @Override
  public void init(HandlerContext context) {
    PinotConfiguration config = context.getConfig();
    _name = context.getName();
    _context = context;
    _http = new ProviderHttp(config.getProperty("http.timeout.ms", 5000L), ProviderHttp.DEFAULT_MAX_RESPONSE_BYTES);
    if (config.getProperty("request.method") == null) {
      config = config.clone();
      config.setProperty("request.method", "POST");
    }
    _call = new HttpTokenHandler.Call(config, "request", PLACEHOLDERS, _name);
    _values = new HashMap<>();
    _values.put("client.id", config.getProperty("client.id", ""));
    List<String> aliases = _call.secretAliases();
    for (String alias : aliases) {
      _values.put("secret:" + alias, new String(context.getSecretResolver().resolve(alias)));
    }
    String tokenPath = config.getProperty("map.token");
    if (tokenPath == null || tokenPath.trim().isEmpty()) {
      throw new IllegalArgumentException("Token source " + _name + ": map.token is required");
    }
    _tokenPath = JsonPath.compile(tokenPath.trim());
    _expiresInPath = compile(config.getProperty("map.expiresIn"));
    _expiresAtPath = compile(config.getProperty("map.expiresAt"));
    _expiresAtFormat = config.getProperty("map.expiresAt.format", "epochSeconds").trim();
    _defaultTtlSeconds = config.getProperty("default.ttl.seconds", 300L);
  }

  @Override
  public AccessToken fetch() {
    Instant now = _context.getClock().instant();
    Map<String, String> values = new HashMap<>(_values);
    values.put("now.epochSeconds", String.valueOf(now.getEpochSecond()));
    values.put("now.epochMillis", String.valueOf(now.toEpochMilli()));
    ProviderHttp.Answer answer;
    try {
      answer = _http.send(_call.build(values, Duration.ofMillis(_http.getTimeoutMs())));
    } catch (IOException e) {
      throw new IllegalStateException("Token source " + _name + ": cannot reach the token endpoint", e);
    }
    if (!answer.isOk()) {
      throw new IllegalStateException("Token source " + _name + ": token endpoint answered " + answer._status);
    }
    DocumentContext document;
    try {
      Object json = JSON_PATH.jsonProvider().parse(answer._body);
      if (!(json instanceof Map)) {
        throw new IllegalArgumentException("not a JSON object");
      }
      document = JsonPath.using(JSON_PATH).parse(json);
    } catch (RuntimeException e) {
      throw new IllegalStateException("Token source " + _name + ": the answer is not a JSON object");
    }
    Object token = document.read(_tokenPath);
    if (!(token instanceof String) || ((String) token).isEmpty()) {
      throw new IllegalStateException("Token source " + _name + ": no token at map.token");
    }
    return new AccessToken((String) token, expiry(document, now));
  }

  private Instant expiry(DocumentContext document, Instant now) {
    try {
      // Read into Object: JsonPath's generic read() would otherwise select String.valueOf(char[])
      Object expiresIn = _expiresInPath != null ? document.read(_expiresInPath) : null;
      if (expiresIn != null) {
        return now.plusSeconds(Long.parseLong(String.valueOf(expiresIn)));
      }
      Object expiresAt = _expiresAtPath != null ? document.read(_expiresAtPath) : null;
      if (expiresAt != null) {
        switch (_expiresAtFormat) {
          case "epochMillis":
            return Instant.ofEpochMilli(Long.parseLong(String.valueOf(expiresAt)));
          case "iso8601":
            return Instant.parse(String.valueOf(expiresAt));
          default:
            return Instant.ofEpochSecond(Long.parseLong(String.valueOf(expiresAt)));
        }
      }
    } catch (NumberFormatException | DateTimeParseException e) {
      throw new IllegalStateException("Token source " + _name + ": the answer's expiry is not a number or date");
    }
    return now.plusSeconds(_defaultTtlSeconds);
  }

  @Nullable
  private static JsonPath compile(@Nullable String path) {
    return path == null || path.trim().isEmpty() ? null : JsonPath.compile(path.trim());
  }
}
