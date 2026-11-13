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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AccessToken;
import org.apache.pinot.plugin.auth.spi.OAuthTokenSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Keeps a token of an [OAuthTokenSource] for Pinot's own calls: fetched once, refreshed when 80 % of its lifetime
/// has passed, with at most one fetch in flight. A failed refresh is retried with back-off, and the last token is kept
/// while it is still valid, so a short outage of the token endpoint does not stop ingestion or segment management.
/// Thread-safe.
final class CachingTokenSource {
  private static final Logger LOGGER = LoggerFactory.getLogger(CachingTokenSource.class);
  static final double REFRESH_AT = 0.8;
  static final int ATTEMPTS = 3;

  private final String _name;
  private final OAuthTokenSource _source;
  private final Clock _clock;
  private final long _initialBackoffMs;

  @Nullable
  private volatile AccessToken _token;
  private volatile Instant _refreshAt = Instant.MIN;
  private final AtomicBoolean _refreshing = new AtomicBoolean();

  CachingTokenSource(String name, OAuthTokenSource source, Clock clock, long initialBackoffMs) {
    _name = name;
    _source = source;
    _clock = clock;
    _initialBackoffMs = initialBackoffMs;
  }

  /// @return a valid token
  /// @throws IllegalStateException when no valid token can be obtained
  String get() {
    AccessToken token = _token;
    Instant now = _clock.instant();
    if (token != null && now.isBefore(_refreshAt)) {
      return token.getToken();
    }
    if (token != null && now.isBefore(token.getExpiresAt())) {
      // Due for refresh but still valid: one caller refreshes, the others keep using the current token
      if (_refreshing.compareAndSet(false, true)) {
        try {
          return refresh(token);
        } finally {
          _refreshing.set(false);
        }
      }
      return token.getToken();
    }
    // No valid token: callers wait for one fetch
    synchronized (this) {
      token = _token;
      if (token != null && _clock.instant().isBefore(_refreshAt)) {
        return token.getToken();
      }
      return refresh(token);
    }
  }

  private String refresh(@Nullable AccessToken current) {
    Instant now = _clock.instant();
    try {
      AccessToken fresh = fetchWithRetry();
      Duration lifetime = Duration.between(now, fresh.getExpiresAt());
      _refreshAt = now.plusMillis((long) (Math.max(0, lifetime.toMillis()) * REFRESH_AT));
      _token = fresh;
      return fresh.getToken();
    } catch (RuntimeException e) {
      if (current != null && _clock.instant().isBefore(current.getExpiresAt())) {
        LOGGER.warn("Token source {}: refresh failed, using the current token until it expires at {}: {}", _name,
            current.getExpiresAt(), e.toString());
        return current.getToken();
      }
      throw new IllegalStateException("Token source " + _name + ": no valid token for Pinot's own calls", e);
    }
  }

  private AccessToken fetchWithRetry() {
    RuntimeException last = null;
    long backoffMs = _initialBackoffMs;
    for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
      try {
        return _source.fetch();
      } catch (RuntimeException e) {
        last = e;
        if (attempt < ATTEMPTS) {
          try {
            Thread.sleep(backoffMs);
          } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            break;
          }
          backoffMs *= 2;
        }
      }
    }
    throw last;
  }
}
