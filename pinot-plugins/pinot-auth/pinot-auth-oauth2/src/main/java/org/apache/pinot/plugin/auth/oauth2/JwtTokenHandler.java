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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Validates JWT bearer tokens of one issuer: signature with the issuer's keys (JWKS, directly or through OpenID
/// Connect discovery), algorithm allow-list, `iss`, `aud` (required), `exp` (required), `nbf` / `iat` with clock skew,
/// optional token type and required claim values. Thread-safe after [#init].
///
/// Settings (`pinot.auth.oauth2.handler.<name>.*`):
/// - `issuer` (required): expected `iss`; also used for discovery
/// - `jwks.url`: key set URL; when unset, taken from `<issuer>/.well-known/openid-configuration`
/// - `audiences` (required unless `require.audience=false`): comma-separated; the token's `aud` must contain one
///   of them
/// - `require.audience` (default true): set false only for a provider whose tokens carry no `aud` at all
/// - `algorithms`: allowed `alg` values, default `RS256,RS384,RS512,PS256,ES256,ES384`. `none` is never accepted; HS*
///   only together with `hmac.secret.alias` (the shared secret, resolved from the secret store)
/// - `clock.skew.seconds`: default 60
/// - `token.type`: required `typ` header, e.g. `at+jwt`; unset accepts `JWT` or no `typ`
/// - `required.claims`: comma-separated `claim=value` pairs, e.g. `hd=example.com`
/// - `accept.id.tokens`: default false; OpenID Connect ID tokens (carrying `nonce`, `at_hash` or `c_hash`) are rejected
///   unless set
/// - `user.claim` (default `sub`), `groups.claim` (default `groups`)
/// - `jwks.cache.ttl.seconds` (default 21600), `jwks.min.refetch.seconds` (default 60): keys are cached and refetched
///   for an unknown key id at most once per interval
/// - `http.connect.timeout.ms`, `http.read.timeout.ms` (default 5000), `http.size.limit.bytes` (default 1048576)
public class JwtTokenHandler implements OAuthTokenHandler {
  public static final String TYPE = "jwt";
  static final String DEFAULT_ALGORITHMS = "RS256,RS384,RS512,PS256,ES256,ES384";
  private static final Set<String> ID_TOKEN_CLAIMS = Set.of("nonce", "at_hash", "c_hash");

  private String _name;
  private String _issuer;
  private String _userClaim;
  private String _groupsClaim;
  private boolean _acceptIdTokens;
  private Map<String, String> _requiredClaims;
  private DefaultJWTProcessor<SecurityContext> _processor;
  private String _challenge;

  @Override
  public void init(HandlerContext context) {
    _name = context.getName();
    PinotConfiguration config = context.getConfig();
    _issuer = required(config, "issuer");
    boolean requireAudience = config.getProperty("require.audience", true);
    String audienceSetting = config.getProperty("audiences", "");
    Set<String> audiences = csv(audienceSetting);
    if (requireAudience && audiences.isEmpty()) {
      throw new IllegalArgumentException("Missing required jwt handler setting 'audiences' (or set require.audience="
          + "false for a provider whose tokens carry no aud)");
    }
    _userClaim = config.getProperty("user.claim", "sub");
    _groupsClaim = config.getProperty("groups.claim", "groups");
    _acceptIdTokens = config.getProperty("accept.id.tokens", false);
    _requiredClaims = parseRequiredClaims(config.getProperty("required.claims", ""));
    _challenge = AuthenticationException.challengeFor(AuthMethod.OAUTH2) + ", error=\"invalid_token\"";

    int connectTimeout = config.getProperty("http.connect.timeout.ms", 5000);
    int readTimeout = config.getProperty("http.read.timeout.ms", 5000);
    int sizeLimit = config.getProperty("http.size.limit.bytes", 1024 * 1024);
    DefaultResourceRetriever retriever = new DefaultResourceRetriever(connectTimeout, readTimeout, sizeLimit);

    Set<JWSAlgorithm> algorithms = new LinkedHashSet<>();
    for (String alg : csv(config.getProperty("algorithms", DEFAULT_ALGORITHMS))) {
      JWSAlgorithm algorithm = JWSAlgorithm.parse(alg);
      if ("none".equalsIgnoreCase(alg)) {
        throw new IllegalArgumentException("Handler " + _name + ": algorithm 'none' is never accepted");
      }
      algorithms.add(algorithm);
    }
    Set<JWSAlgorithm> hmac = algorithms.stream().filter(JWSAlgorithm.Family.HMAC_SHA::contains)
        .collect(Collectors.toSet());
    Set<JWSAlgorithm> asymmetric = new LinkedHashSet<>(algorithms);
    asymmetric.removeAll(hmac);

    _processor = new DefaultJWTProcessor<>();
    String tokenType = config.getProperty("token.type");
    if (tokenType != null && !tokenType.trim().isEmpty()) {
      _processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(tokenType.trim())));
    } else {
      _processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT, null));
    }
    if (!hmac.isEmpty()) {
      // A shared secret is required for HS*: without it an attacker could sign with the public key as HMAC secret
      String alias = config.getProperty("hmac.secret.alias");
      if (alias == null || alias.trim().isEmpty()) {
        throw new IllegalArgumentException("Handler " + _name + ": HS algorithms " + hmac
            + " need hmac.secret.alias (a shared secret); remove them from algorithms otherwise");
      }
      if (!asymmetric.isEmpty()) {
        throw new IllegalArgumentException("Handler " + _name + ": do not mix HS algorithms with asymmetric ones in "
            + "one handler; configure a separate handler");
      }
      byte[] secret = new String(context.getSecretResolver().resolve(alias.trim())).getBytes(StandardCharsets.UTF_8);
      _processor.setJWSKeySelector(new JWSVerificationKeySelector<>(hmac, new ImmutableSecret<>(secret)));
    } else {
      URL jwksUrl = jwksUrl(config, retriever);
      long ttlMs = config.getProperty("jwks.cache.ttl.seconds", 21600L) * 1000;
      long minRefetchMs = config.getProperty("jwks.min.refetch.seconds", 60L) * 1000;
      JWKSource<SecurityContext> keys = JWKSourceBuilder.<SecurityContext>create(jwksUrl, retriever)
          .cache(ttlMs, Math.min(readTimeout + connectTimeout, ttlMs))
          .rateLimited(minRefetchMs)
          .retrying(true)
          .build();
      _processor.setJWSKeySelector(new JWSVerificationKeySelector<>(asymmetric, keys));
    }

    Set<String> requiredClaimNames = new HashSet<>(Arrays.asList("exp", _userClaim));
    requiredClaimNames.addAll(_requiredClaims.keySet());
    // With require.audience=false and no audiences configured, aud is not checked; configured audiences are always
    // enforced
    DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>(
        audiences.isEmpty() ? null : audiences,
        new JWTClaimsSet.Builder().issuer(_issuer).build(), requiredClaimNames, null);
    claimsVerifier.setMaxClockSkew(config.getProperty("clock.skew.seconds", 60));
    _processor.setJWTClaimsSetVerifier(claimsVerifier);
  }

  /// The issuer this handler accepts; the router sends a JWT only to the handler of its issuer.
  public String getIssuer() {
    return _issuer;
  }

  @Nullable
  @Override
  public TokenIdentity validate(String token) {
    JWTClaimsSet claims;
    try {
      claims = _processor.process(token, null);
    } catch (ParseException e) {
      throw reject("malformed token");
    } catch (BadJWTException e) {
      throw reject(e.getMessage());
    } catch (BadJOSEException e) {
      throw reject(e.getMessage());
    } catch (RateLimitReachedException e) {
      // An unknown key id was already refetched within the last interval: the key is not published by the provider
      throw reject("signing key not published by the identity provider");
    } catch (JOSEException e) {
      throw new AuthenticationException("Identity provider unavailable for " + _name + ": cannot check the token "
          + "signature", _challenge, e);
    }
    for (Map.Entry<String, String> required : _requiredClaims.entrySet()) {
      Object value = claims.getClaim(required.getKey());
      if (value == null || !required.getValue().equals(String.valueOf(value))) {
        throw reject("claim '" + required.getKey() + "' does not have the required value");
      }
    }
    if (!_acceptIdTokens && ID_TOKEN_CLAIMS.stream().anyMatch(c -> claims.getClaim(c) != null)) {
      throw reject("ID tokens are not accepted by this handler");
    }
    Object user = claims.getClaim(_userClaim);
    if (!(user instanceof String) || ((String) user).trim().isEmpty()) {
      throw reject("claim '" + _userClaim + "' is missing or not a string");
    }
    return new TokenIdentity((String) user, groups(claims.getClaim(_groupsClaim)), scopes(claims), Instant.ofEpochMilli(
        claims.getExpirationTime().getTime()), claims.getIssuer(), new LinkedHashMap<>(claims.getClaims()));
  }

  private AuthenticationException reject(String reason) {
    return new AuthenticationException("Invalid token (" + _name + "): " + reason, _challenge);
  }

  private URL jwksUrl(PinotConfiguration config, DefaultResourceRetriever retriever) {
    String configured = config.getProperty("jwks.url");
    try {
      if (configured != null && !configured.trim().isEmpty()) {
        return new URL(configured.trim());
      }
      String base = _issuer.endsWith("/") ? _issuer.substring(0, _issuer.length() - 1) : _issuer;
      Resource discovery = retriever.retrieveResource(new URL(base + "/.well-known/openid-configuration"));
      Map<String, Object> document = JSONObjectUtils.parse(discovery.getContent());
      String discoveredIssuer = JSONObjectUtils.getString(document, "issuer");
      if (!_issuer.equals(discoveredIssuer)) {
        throw new IllegalStateException("Handler " + _name + ": discovery document names issuer '" + discoveredIssuer
            + "', expected '" + _issuer + "'");
      }
      String jwksUri = JSONObjectUtils.getString(document, "jwks_uri");
      if (jwksUri == null) {
        throw new IllegalStateException("Handler " + _name + ": discovery document has no jwks_uri");
      }
      return new URL(jwksUri);
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("Handler " + _name + ": cannot load the OpenID Connect discovery document of '"
          + _issuer + "'; set jwks.url or check the issuer", e);
    }
  }

  private static Set<String> groups(@Nullable Object value) {
    if (value instanceof Collection) {
      return ((Collection<?>) value).stream().map(String::valueOf).collect(Collectors.toCollection(LinkedHashSet::new));
    }
    if (value instanceof String) {
      return csv((String) value);
    }
    return Collections.emptySet();
  }

  private static Set<String> scopes(JWTClaimsSet claims) {
    Object scope = claims.getClaim("scope");
    if (scope instanceof String) {
      return new LinkedHashSet<>(Arrays.asList(((String) scope).trim().split("\\s+")));
    }
    return groups(claims.getClaim("scp"));
  }

  private static String required(PinotConfiguration config, String key) {
    String value = config.getProperty(key);
    if (value == null || value.trim().isEmpty()) {
      throw new IllegalArgumentException("Missing required jwt handler setting '" + key + "'");
    }
    return value.trim();
  }

  static Set<String> csv(String value) {
    List<String> parts = new ArrayList<>();
    for (String part : value.split(",")) {
      if (!part.trim().isEmpty()) {
        parts.add(part.trim());
      }
    }
    return new LinkedHashSet<>(parts);
  }

  static Map<String, String> parseRequiredClaims(String value) {
    Map<String, String> claims = new LinkedHashMap<>();
    for (String pair : csv(value)) {
      int eq = pair.indexOf('=');
      if (eq <= 0) {
        throw new IllegalArgumentException("required.claims entries must be claim=value, got '" + pair + "'");
      }
      claims.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
    }
    return claims;
  }
}
