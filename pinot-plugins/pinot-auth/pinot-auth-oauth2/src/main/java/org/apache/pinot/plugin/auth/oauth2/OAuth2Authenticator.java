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
import java.util.IdentityHashMap;
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
/// (`jwt`, `google`, `introspection`, `http`) or custom (`java`, loaded from their own jar). Thread-safe after [#init].
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
///   handler jars (default `auth-handlers` next to the first plugins directory, e.g. `<Pinot home>/auth-handlers`;
///   never inside a plugins directory, whose jars Pinot puts on its own classpath)
/// - `handler.<name>.type`: `jwt` (default, see [JwtTokenHandler]), `google` (see [GoogleHandlerPreset]),
///   `introspection` (see [IntrospectionTokenHandler]), `http` (see [HttpTokenHandler]) or `java`
/// - for `java`: `handler.<name>.class` (required), `handler.<name>.jar.dir` (default `<handlers.dir>/<name>`),
///   `handler.<name>.issuer` and / or `handler.<name>.token.pattern`; every other `handler.<name>.*` setting is passed
///   to the handler. `handler.<name>.allow.classpath=true` loads the class from Pinot's own classpath instead (only for
///   handlers shipped with Pinot)
///
/// Each handler's result is mapped to the Pinot principal by its [IdentityMapper] (`handler.<name>.user.rules`,
/// `groups.*`, `required.scopes`, `scopes.as.groups`, `service.*`), so user and group names match the authorization
/// rules.
public class OAuth2Authenticator implements PinotAuthenticator {
  public static final int DEFAULT_MAX_TOKEN_BYTES = 16 * 1024;
  public static final String HANDLERS_DIR_NAME = "auth-handlers";
  static final String TYPE_JAVA = "java";

  private final Map<String, GuardedHandler> _handlersByIssuer = new LinkedHashMap<>();
  private final List<RoutedHandler> _issuerlessHandlers = new ArrayList<>();
  private final List<GuardedHandler> _allHandlers = new ArrayList<>();
  private final List<HandlerClassLoader> _classLoaders = new ArrayList<>();
  /// Identity mapping of each handler.
  private final Map<GuardedHandler, IdentityMapper> _mappers = new IdentityHashMap<>();
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
    String handlersDirSetting = config.getProperty("handlers.dir");
    File handlersDir = handlersDirSetting != null && !handlersDirSetting.trim().isEmpty()
        ? new File(handlersDirSetting.trim()) : defaultHandlersDir();
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
    boolean cacheDisabled = false;
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
      case IntrospectionTokenHandler.TYPE: {
        IntrospectionTokenHandler introspection = new IntrospectionTokenHandler();
        introspection.init(new SimpleHandlerContext(name, handlerConfig, secretResolver));
        handler = introspection;
        issuer = introspection.getIssuer();
        // The handler caches itself (positive and negative answers); a second cache here would only hide its counters
        cacheDisabled = true;
        break;
      }
      case HttpTokenHandler.TYPE: {
        HttpTokenHandler http = new HttpTokenHandler();
        http.init(new SimpleHandlerContext(name, handlerConfig, secretResolver));
        handler = http;
        issuer = http.getIssuer();
        cacheDisabled = true;
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
        cacheDisabled ? 0 : handlerConfig.getProperty("cache.ttl.seconds", defaultCacheSeconds) * 1000);
    _allHandlers.add(guarded);
    _mappers.put(guarded, new IdentityMapper(name, handlerConfig));
    boolean hasIssuer = issuer != null && !issuer.trim().isEmpty();
    if (hasIssuer) {
      if (_handlersByIssuer.putIfAbsent(issuer.trim(), guarded) != null) {
        throw new IllegalArgumentException("Two handlers claim issuer '" + issuer.trim() + "'");
      }
    }
    // Opaque tokens carry no issuer, so a handler that checks them with the provider (introspection, http) also takes
    // the tokens no issuer routes, unless opaque.tokens=false
    boolean checksWithProvider = IntrospectionTokenHandler.TYPE.equals(type) || HttpTokenHandler.TYPE.equals(type);
    if (!hasIssuer || handlerConfig.getProperty("opaque.tokens", checksWithProvider)) {
      String pattern = handlerConfig.getProperty("token.pattern");
      _issuerlessHandlers.add(new RoutedHandler(guarded,
          pattern == null || pattern.trim().isEmpty() ? null : Pattern.compile(pattern.trim())));
    }
  }

  /// The default directory of custom handler jars: `auth-handlers` next to the first plugins directory
  /// (`plugins.dir`), e.g. `<Pinot home>/auth-handlers`. Handler jars must not live inside a plugins directory: Pinot's
  /// launcher puts every jar found there on Pinot's own classpath and the plugin manager registers each such
  /// directory as a plugin, which would undo the isolation of handlers from Pinot's dependencies.
  static File defaultHandlersDir() {
    String pluginsDirs = System.getProperty(PluginManager.PLUGINS_DIR_PROPERTY_NAME);
    if (pluginsDirs != null && !pluginsDirs.trim().isEmpty()) {
      File parent = new File(pluginsDirs.split(";")[0].trim()).getAbsoluteFile().getParentFile();
      if (parent != null) {
        return new File(parent, HANDLERS_DIR_NAME);
      }
    }
    return new File(HANDLERS_DIR_NAME).getAbsoluteFile();
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
    return route(token);
  }

  private PinotPrincipal route(String token) {
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
      return _mappers.get(handler).map(identity);
    }
    for (RoutedHandler routed : _issuerlessHandlers) {
      if (routed._pattern != null && !routed._pattern.matcher(token).matches()) {
        continue;
      }
      TokenIdentity identity = routed._handler.validate(token);
      if (identity != null) {
        return _mappers.get(routed._handler).map(identity);
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
