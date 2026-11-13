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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthMetrics;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Wraps every token handler so that no handler can let a request through by failing: a handler exception or error,
/// or a call that exceeds `timeout.ms`, becomes a rejection (HTTP 401), never an accepted token. Optionally caches
/// accepted results by token hash for `cache.ttl.seconds`, never beyond the token's expiry. Calls run with the
/// handler's own class loader as context class loader. Thread-safe.
final class GuardedHandler {
  private static final Logger LOGGER = LoggerFactory.getLogger(GuardedHandler.class);
  private static final int MAX_CACHE_ENTRIES = 10_000;
  private static final long EXPIRY_SKEW_SECONDS = 60;

  private final String _name;
  private final OAuthTokenHandler _handler;
  private final ClassLoader _classLoader;
  private final ExecutorService _executor;
  private final long _timeoutMs;
  private final long _cacheTtlMs;
  private final String _metrics;
  private final String _challenge =
      AuthenticationException.challengeFor(AuthMethod.OAUTH2) + ", error=\"invalid_token\"";
  private final Map<String, CachedIdentity> _cache = new LinkedHashMap<String, CachedIdentity>(16, 0.75f, true) {
    @Override
    protected boolean removeEldestEntry(Map.Entry<String, CachedIdentity> eldest) {
      return size() > MAX_CACHE_ENTRIES;
    }
  };

  private static final class CachedIdentity {
    final TokenIdentity _identity;
    final long _validUntilMs;

    CachedIdentity(TokenIdentity identity, long validUntilMs) {
      _identity = identity;
      _validUntilMs = validUntilMs;
    }
  }

  GuardedHandler(String name, OAuthTokenHandler handler, ClassLoader classLoader, ExecutorService executor,
      long timeoutMs, long cacheTtlMs) {
    _name = name;
    _metrics = AuthMetrics.handler(name);
    _handler = handler;
    _classLoader = classLoader;
    _executor = executor;
    _timeoutMs = timeoutMs;
    _cacheTtlMs = cacheTtlMs;
  }

  String getName() {
    return _name;
  }

  /// @return the identity, or `null` when the handler does not recognise the token
  /// @throws AuthenticationException when the token is rejected, the handler fails or it times out
  @Nullable
  TokenIdentity validate(String token) {
    String key = _cacheTtlMs > 0 ? hash(token) : null;
    long now = System.currentTimeMillis();
    if (key != null) {
      synchronized (_cache) {
        CachedIdentity cached = _cache.get(key);
        if (cached != null && cached._validUntilMs > now) {
          AuthMetrics.mark(_metrics + "cacheHits");
          return cached._identity;
        }
      }
    }
    TokenIdentity identity = measuredCall(token);
    if (key != null && identity != null) {
      long until = Math.min(now + _cacheTtlMs, identity.getExpiresAt().toEpochMilli());
      if (until > now) {
        synchronized (_cache) {
          _cache.put(key, new CachedIdentity(identity, until));
        }
      }
    }
    // Safety net for custom handlers that return an identity long past its expiry; the clock skew matches the jwt
    // handler's default so a token accepted within the skew is not rejected here
    if (identity != null
        && identity.getExpiresAt().plusSeconds(EXPIRY_SKEW_SECONDS).isBefore(Instant.ofEpochMilli(now))) {
      throw new AuthenticationException("Invalid token (" + _name + "): expired", _challenge);
    }
    return identity;
  }

  /// Calls the handler and records the outcome: accepted, rejected, or unavailable (provider failure or timeout).
  @Nullable
  private TokenIdentity measuredCall(String token) {
    long start = System.nanoTime();
    try {
      TokenIdentity identity = call(token);
      if (identity != null) {
        AuthMetrics.mark(_metrics + "accepted");
      }
      return identity;
    } catch (AuthenticationException e) {
      String message = e.getMessage();
      boolean unavailable = message != null
          && (message.startsWith("Identity provider unavailable") || message.startsWith("Identity provider timeout"));
      AuthMetrics.mark(_metrics + (unavailable ? "unavailable" : "rejected"));
      throw e;
    } finally {
      AuthMetrics.time(_metrics + "providerLatencyMs", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
    }
  }

  @Nullable
  private TokenIdentity call(String token) {
    Future<TokenIdentity> result = _executor.submit(() -> {
      Thread thread = Thread.currentThread();
      ClassLoader previous = thread.getContextClassLoader();
      thread.setContextClassLoader(_classLoader);
      try {
        return _handler.validate(token);
      } finally {
        thread.setContextClassLoader(previous);
      }
    });
    try {
      return result.get(_timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      result.cancel(true);
      throw new AuthenticationException("Identity provider timeout (" + _name + ")", _challenge);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AuthenticationException("Interrupted while checking the token (" + _name + ")", _challenge);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof AuthenticationException) {
        throw (AuthenticationException) cause;
      }
      // Any other failure of a handler is a rejection, never a pass
      LOGGER.warn("Token handler {} failed; rejecting the request", _name, cause);
      throw new AuthenticationException("Token handler error (" + _name + ")", _challenge);
    }
  }

  void close() {
    try {
      _handler.close();
    } catch (Exception e) {
      LOGGER.warn("Failed to close token handler {}", _name, e);
    }
  }

  static String hash(String token) {
    try {
      return Base64.getEncoder().encodeToString(
          MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
