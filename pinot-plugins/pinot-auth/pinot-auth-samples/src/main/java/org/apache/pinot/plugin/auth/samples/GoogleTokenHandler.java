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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.samples.support.HttpCalls;
import org.apache.pinot.plugin.auth.samples.support.Json;
import org.apache.pinot.plugin.auth.samples.support.JsonMapping;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Sample handler for Google **access tokens** (`ya29.…`). These are opaque, so they cannot be checked with keys
/// like Google ID tokens (use the built-in `google` handler type for those); this handler asks Google's token-info
/// endpoint instead. It also shows the pattern for any provider whose tokens are opaque and that offers a
/// token-info / introspection call.
///
/// A token is accepted when the token-info answer is 2xx and:
/// - its `aud` or `azp` is one of `client.ids` (tokens issued to other applications are refused);
/// - `expires_in` is positive;
/// - it carries an `email` with `email_verified` true (the token must have been granted the `email` scope);
/// - with `hosted.domain`, the email belongs to that Google Workspace domain.
///
/// The user is the email; scopes come from `scope`. Google reports no groups: map groups with identity mapping.
///
/// Settings: `client.ids` (required, comma list), `hosted.domain`, `token.pattern` (default `ya29\..+`; other tokens
/// return `null`), `tokeninfo.url` (default `https://oauth2.googleapis.com/tokeninfo`), `http.timeout.ms` (3000).
/// Thread-safe after [#init].
public class GoogleTokenHandler implements OAuthTokenHandler {
  public static final String DEFAULT_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo";

  private String _name;
  private String _challenge;
  private Clock _clock;
  private HttpCalls _http;
  private Set<String> _clientIds;
  @Nullable
  private String _hostedDomain;
  private Pattern _tokenPattern;
  private String _tokenInfoUrl;

  @Override
  public void init(HandlerContext context) {
    PinotConfiguration config = context.getConfig();
    _name = context.getName();
    _clock = context.getClock();
    _challenge = AuthenticationException.challengeFor(AuthMethod.OAUTH2) + ", error=\"invalid_token\"";
    _http = new HttpCalls(Duration.ofMillis(config.getProperty("http.timeout.ms", 3000L)));
    _clientIds = CustomIdpTokenHandler.csv(CustomIdpTokenHandler.required(config, "client.ids"));
    String domain = CustomIdpTokenHandler.optional(config, "hosted.domain");
    _hostedDomain = domain == null ? null : domain.toLowerCase(Locale.ROOT);
    _tokenPattern = Pattern.compile(config.getProperty("token.pattern", "ya29\\..+"));
    _tokenInfoUrl = config.getProperty("tokeninfo.url", DEFAULT_TOKENINFO_URL).trim();
  }

  @Nullable
  @Override
  public TokenIdentity validate(String token) {
    if (!_tokenPattern.matcher(token).matches()) {
      return null;
    }
    HttpCalls.Response response;
    try {
      // POST keeps the token out of URLs and access logs
      response = _http.postForm(_tokenInfoUrl, Collections.singletonMap("access_token", token),
          Collections.emptyMap());
    } catch (IOException | RuntimeException e) {
      throw new AuthenticationException("Identity provider unavailable for " + _name + ": token-info call failed",
          _challenge, e);
    }
    if (response.getStatus() == 400 || response.getStatus() == 401) {
      // Google answers 400 invalid_token for expired, revoked or malformed tokens
      throw reject("rejected by Google");
    }
    if (!response.isOk()) {
      throw new AuthenticationException("Identity provider unavailable for " + _name + ": token-info call answered "
          + response.getStatus(), _challenge);
    }
    Map<String, Object> info;
    try {
      info = Json.parseObject(response.getBody());
    } catch (IllegalArgumentException e) {
      throw new AuthenticationException("Identity provider unavailable for " + _name + ": token-info answer is not "
          + "JSON", _challenge);
    }
    String audience = JsonMapping.getString(info, "aud");
    String authorizedParty = JsonMapping.getString(info, "azp");
    if (!_clientIds.contains(audience) && !_clientIds.contains(authorizedParty)) {
      throw reject("issued to another application");
    }
    Long expiresIn = JsonMapping.getLong(info, "expires_in");
    if (expiresIn == null || expiresIn <= 0) {
      throw reject("expired");
    }
    String email = JsonMapping.getString(info, "email");
    if (email == null || !"true".equals(JsonMapping.getString(info, "email_verified"))) {
      throw reject("no verified email (grant the email scope)");
    }
    if (_hostedDomain != null && !email.toLowerCase(Locale.ROOT).endsWith("@" + _hostedDomain)) {
      throw reject("not in the " + _hostedDomain + " domain");
    }
    Map<String, Object> attributes = new LinkedHashMap<>(info);
    attributes.put("handler", _name);
    return new TokenIdentity(email, Collections.emptySet(), JsonMapping.getStrings(info, "scope"),
        _clock.instant().plusSeconds(expiresIn), "https://accounts.google.com", attributes);
  }

  private AuthenticationException reject(String reason) {
    return new AuthenticationException("Invalid token (" + _name + "): " + reason, _challenge);
  }
}
