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

import com.nimbusds.jwt.JWTParser;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;


/// The `oauth2` authentication method: routes each bearer token to the configured token handlers and turns the result
/// into a [PinotPrincipal]. Several identity providers are several handlers under this one method. Thread-safe after
/// [#init].
///
/// Routing:
/// - tokens larger than `max.token.bytes` (default 16384) are rejected;
/// - a JWT goes only to the jwt handler configured for its (not yet verified) `iss`; an unknown issuer is rejected;
/// - any other token goes to the non-jwt handlers whose `token.pattern` (regex) matches it, or to all of them in
///   configured order; the first handler that recognises the token decides, a rejection is final.
///
/// Settings (`pinot.auth.oauth2.*`): `handlers` (comma-separated names, in order), `max.token.bytes`, and per handler
/// `handler.<name>.type` (`jwt`) plus that type's settings, see [JwtTokenHandler].
public class OAuth2Authenticator implements PinotAuthenticator {
  public static final int DEFAULT_MAX_TOKEN_BYTES = 16 * 1024;

  private final Map<String, JwtTokenHandler> _jwtHandlersByIssuer = new LinkedHashMap<>();
  private final List<RoutedHandler> _opaqueHandlers = new ArrayList<>();
  private final List<OAuthTokenHandler> _allHandlers = new ArrayList<>();
  private int _maxTokenBytes;
  private String _challenge;

  private static final class RoutedHandler {
    final OAuthTokenHandler _handler;
    @Nullable
    final Pattern _pattern;

    RoutedHandler(OAuthTokenHandler handler, @Nullable Pattern pattern) {
      _handler = handler;
      _pattern = pattern;
    }
  }

  @Override
  public AuthMethod getMethod() {
    return AuthMethod.OAUTH2;
  }

  @Override
  public void init(PinotConfiguration config, SecretResolver secretResolver) {
    _maxTokenBytes = config.getProperty("max.token.bytes", DEFAULT_MAX_TOKEN_BYTES);
    _challenge = AuthenticationException.challengeFor(AuthMethod.OAUTH2) + ", error=\"invalid_token\"";
    String names = config.getProperty("handlers");
    if (names == null || JwtTokenHandler.csv(names).isEmpty()) {
      throw new IllegalArgumentException("pinot.auth.oauth2.handlers must name at least one token handler");
    }
    for (String name : JwtTokenHandler.csv(names)) {
      PinotConfiguration handlerConfig = config.subset("handler." + name);
      String type = handlerConfig.getProperty("type", JwtTokenHandler.TYPE);
      if (!JwtTokenHandler.TYPE.equals(type)) {
        throw new IllegalArgumentException("Handler " + name + ": unsupported type '" + type + "'");
      }
      JwtTokenHandler handler = new JwtTokenHandler();
      handler.init(new SimpleHandlerContext(name, handlerConfig, secretResolver));
      if (_jwtHandlersByIssuer.putIfAbsent(handler.getIssuer(), handler) != null) {
        throw new IllegalArgumentException("Two jwt handlers for issuer '" + handler.getIssuer() + "'");
      }
      _allHandlers.add(handler);
    }
  }

  /// Registers a non-jwt handler (opaque tokens); used by the other handler types.
  void addOpaqueHandler(OAuthTokenHandler handler, @Nullable String tokenPattern) {
    _opaqueHandlers.add(new RoutedHandler(handler, tokenPattern == null ? null : Pattern.compile(tokenPattern)));
    _allHandlers.add(handler);
  }

  @Override
  public PinotPrincipal authenticate(AuthCredential credential) {
    String token = credential.getValue();
    if (token.getBytes(StandardCharsets.UTF_8).length > _maxTokenBytes) {
      throw new AuthenticationException("Token larger than " + _maxTokenBytes + " bytes", _challenge);
    }
    return toPrincipal(route(token));
  }

  private TokenIdentity route(String token) {
    String issuer = unverifiedIssuer(token);
    if (issuer != null) {
      JwtTokenHandler handler = _jwtHandlersByIssuer.get(issuer);
      if (handler == null) {
        throw new AuthenticationException("Token issuer is not configured", _challenge);
      }
      TokenIdentity identity = handler.validate(token);
      if (identity == null) {
        throw new AuthenticationException("Token not accepted", _challenge);
      }
      return identity;
    }
    for (RoutedHandler routed : _opaqueHandlers) {
      if (routed._pattern != null && !routed._pattern.matcher(token).matches()) {
        continue;
      }
      TokenIdentity identity = routed._handler.validate(token);
      if (identity != null) {
        return identity;
      }
    }
    throw new AuthenticationException("Token not recognised by any configured identity provider", _challenge);
  }

  /// The `iss` of a JWT before verification, used only to pick the handler; `null` for a token that is not a JWT.
  @Nullable
  static String unverifiedIssuer(String token) {
    if (token.chars().filter(c -> c == '.').count() != 2) {
      return null;
    }
    try {
      return JWTParser.parse(token).getJWTClaimsSet().getIssuer();
    } catch (ParseException e) {
      return null;
    }
  }

  /// Minimal mapping: user and groups as delivered by the handler. Name rules and service-account detection are added
  /// by the identity mapping.
  private PinotPrincipal toPrincipal(TokenIdentity identity) {
    Map<String, Object> claims = new LinkedHashMap<>(identity.getAttributes());
    return new PinotPrincipal(identity.getUser(), identity.getGroups(), AuthMethod.OAUTH2, false, claims);
  }

  @Override
  public void close() {
    for (OAuthTokenHandler handler : _allHandlers) {
      try {
        handler.close();
      } catch (Exception e) {
        // best effort
      }
    }
  }
}
