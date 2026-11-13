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
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
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
import org.apache.pinot.spi.plugin.PluginManager;


/// The `oauth2` authentication method: routes each bearer token to one of the configured token handlers and turns the
/// result into a [PinotPrincipal]. Several identity providers are several handlers under this one method, built-in
/// (`jwt`, `google`) or custom (`java`, loaded from their own jar). Thread-safe after [#init].
///
/// Routing:
/// - tokens larger than `max.token.bytes` (default 16384) are rejected;
/// - a JWT goes only to the handler whose `issuer` equals its (not yet verified) `iss`, whatever the handler type; an
///   issuer no handler claims is rejected;
/// - any other token (opaque, or a JWT without `iss`) goes to the handlers that claim no issuer: those whose
///   `token.pattern` (regex) matches it, or all of them in configured order; the first handler that recognises the
///   token decides and a rejection is final.
///
/// Every handler runs guarded (see [GuardedHandler]): a failure or a timeout (`timeout.ms`, default 5000) rejects the
/// token, it never lets it through; accepted results are cached for `cache.ttl.seconds` (default 60 for `java`, 0
/// otherwise).
///
/// Settings (`pinot.auth.oauth2.*`):
/// - `handlers`: comma-separated handler names, in order; `max.token.bytes`; `handlers.dir`: directory of custom
///   handler jars (default `<plugins.dir>/pinot-auth-handlers`)
/// - `handler.<name>.type`: `jwt` (default, see [JwtTokenHandler]), `google` (see [GoogleHandlerPreset]) or `java`
/// - for `java`: `handler.<name>.class` (required), `handler.<name>.jar.dir` (default `<handlers.dir>/<name>`),
///   `handler.<name>.issuer` and / or `handler.<name>.token.pattern`; every other `handler.<name>.*` setting is passed
///   to the handler. `handler.<name>.allow.classpath=true` loads the class from Pinot's own classpath instead (only for
///   handlers shipped with Pinot)
public class OAuth2Authenticator implements PinotAuthenticator {
  public static final int DEFAULT_MAX_TOKEN_BYTES = 16 * 1024;
  public static final String HANDLERS_DIR_NAME = "pinot-auth-handlers";
  static final String TYPE_JAVA = "java";

  private final Map<String, GuardedHandler> _handlersByIssuer = new LinkedHashMap<>();
  private final List<RoutedHandler> _issuerlessHandlers = new ArrayList<>();
  private final List<GuardedHandler> _allHandlers = new ArrayList<>();
  private final List<HandlerClassLoader> _classLoaders = new ArrayList<>();
  private ExecutorService _executor;
  private int _maxTokenBytes;
  private String _challenge;

  private static final class RoutedHandler {
    final GuardedHandler _handler;
    @Nullable
    final Pattern _pattern;

    RoutedHandler(GuardedHandler handler, @Nullable Pattern pattern) {
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
    AtomicInteger threadIds = new AtomicInteger();
    _executor = Executors.newCachedThreadPool(runnable -> {
      Thread thread = new Thread(runnable, "oauth2-token-handler-" + threadIds.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    });
    String names = config.getProperty("handlers");
    if (names == null || JwtTokenHandler.csv(names).isEmpty()) {
      throw new IllegalArgumentException("pinot.auth.oauth2.handlers must name at least one token handler");
    }
    File handlersDir = new File(config.getProperty("handlers.dir",
        System.getProperty(PluginManager.PLUGINS_DIR_PROPERTY_NAME, "plugins") + File.separator + HANDLERS_DIR_NAME));
    for (String name : JwtTokenHandler.csv(names)) {
      addHandler(name, config.subset("handler." + name), secretResolver, handlersDir);
    }
  }

  private void addHandler(String name, PinotConfiguration handlerConfig, SecretResolver secretResolver,
      File handlersDir) {
    String type = handlerConfig.getProperty("type", JwtTokenHandler.TYPE);
    OAuthTokenHandler handler;
    ClassLoader classLoader = getClass().getClassLoader();
    String issuer;
    long defaultCacheSeconds = 0;
    switch (type) {
      case JwtTokenHandler.TYPE:
      case GoogleHandlerPreset.TYPE: {
        PinotConfiguration jwtConfig =
            GoogleHandlerPreset.TYPE.equals(type) ? GoogleHandlerPreset.toJwtConfig(handlerConfig) : handlerConfig;
        JwtTokenHandler jwt = new JwtTokenHandler();
        jwt.init(new SimpleHandlerContext(name, jwtConfig, secretResolver));
        handler = jwt;
        issuer = jwt.getIssuer();
        break;
      }
      case TYPE_JAVA: {
        String className = handlerConfig.getProperty("class");
        if (className == null || className.trim().isEmpty()) {
          throw new IllegalArgumentException("Handler " + name + ": type java needs class");
        }
        if (!handlerConfig.getProperty("allow.classpath", false)) {
          File jarDir = new File(handlerConfig.getProperty("jar.dir", new File(handlersDir, name).getPath()));
          HandlerClassLoader loader = HandlerClassLoader.forDirectory(jarDir, classLoader);
          _classLoaders.add(loader);
          classLoader = loader;
        }
        handler = instantiate(name, className.trim(), classLoader);
        Thread thread = Thread.currentThread();
        ClassLoader previous = thread.getContextClassLoader();
        thread.setContextClassLoader(classLoader);
        try {
          handler.init(new SimpleHandlerContext(name, handlerConfig, secretResolver));
        } finally {
          thread.setContextClassLoader(previous);
        }
        issuer = handlerConfig.getProperty("issuer");
        defaultCacheSeconds = 60;
        break;
      }
      default:
        throw new IllegalArgumentException("Handler " + name + ": unsupported type '" + type + "'");
    }
    GuardedHandler guarded = new GuardedHandler(name, handler, classLoader, _executor,
        handlerConfig.getProperty("timeout.ms", 5000L),
        handlerConfig.getProperty("cache.ttl.seconds", defaultCacheSeconds) * 1000);
    _allHandlers.add(guarded);
    if (issuer != null && !issuer.trim().isEmpty()) {
      if (_handlersByIssuer.putIfAbsent(issuer.trim(), guarded) != null) {
        throw new IllegalArgumentException("Two handlers claim issuer '" + issuer.trim() + "'");
      }
    } else {
      String pattern = handlerConfig.getProperty("token.pattern");
      _issuerlessHandlers.add(new RoutedHandler(guarded,
          pattern == null || pattern.trim().isEmpty() ? null : Pattern.compile(pattern.trim())));
    }
  }

  private static OAuthTokenHandler instantiate(String name, String className, ClassLoader classLoader) {
    Object instance;
    try {
      instance = Class.forName(className, true, classLoader).getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException | LinkageError e) {
      throw new IllegalStateException("Handler " + name + ": cannot create '" + className + "'", e);
    }
    if (!(instance instanceof OAuthTokenHandler)) {
      throw new IllegalStateException("Handler " + name + ": '" + className + "' does not implement "
          + OAuthTokenHandler.class.getName());
    }
    return (OAuthTokenHandler) instance;
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
      GuardedHandler handler = _handlersByIssuer.get(issuer);
      if (handler == null) {
        throw new AuthenticationException("Token issuer is not configured", _challenge);
      }
      TokenIdentity identity = handler.validate(token);
      if (identity == null) {
        throw new AuthenticationException("Token not accepted", _challenge);
      }
      return identity;
    }
    for (RoutedHandler routed : _issuerlessHandlers) {
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
    for (GuardedHandler handler : _allHandlers) {
      handler.close();
    }
    for (HandlerClassLoader loader : _classLoaders) {
      try {
        loader.close();
      } catch (Exception e) {
        // best effort
      }
    }
    if (_executor != null) {
      _executor.shutdownNow();
    }
  }
}
