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
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Answers of a provider call, cached by the SHA-256 of the token (the token itself is never kept): an accepted token
/// for `cache.ttl.seconds` (default 60) but never past its expiry, a rejected token for `negative.cache.seconds`
/// (default 10), at most `cache.max.entries` (default 10000) answers, least recently used evicted first. Provider
/// failures must not be put here. Thread-safe.
final class TokenResultCache {
  /// A cached answer: an identity, or `null` for a rejected token.
  static final class Entry {
    @Nullable
    final TokenIdentity _identity;
    final long _validUntilMs;

    Entry(@Nullable TokenIdentity identity, long validUntilMs) {
      _identity = identity;
      _validUntilMs = validUntilMs;
    }
  }

  private final long _ttlMs;
  private final long _negativeTtlMs;
  private final Map<String, Entry> _entries;

  TokenResultCache(PinotConfiguration config) {
    _ttlMs = config.getProperty("cache.ttl.seconds", 60L) * 1000;
    _negativeTtlMs = config.getProperty("negative.cache.seconds", 10L) * 1000;
    int maxEntries = config.getProperty("cache.max.entries", 10_000);
    _entries = Collections.synchronizedMap(new LinkedHashMap<String, Entry>(16, 0.75f, true) {
      @Override
      protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
        return size() > maxEntries;
      }
    });
  }

  long getTtlMs() {
    return _ttlMs;
  }

  /// @return the cached answer, or `null` when there is none or it has run out
  @Nullable
  Entry get(String key, long nowMs) {
    Entry entry = _entries.get(key);
    return entry != null && entry._validUntilMs > nowMs ? entry : null;
  }

  void putAccepted(String key, TokenIdentity identity, long nowMs) {
    long validUntilMs = Math.min(nowMs + _ttlMs, identity.getExpiresAt().toEpochMilli());
    if (validUntilMs > nowMs) {
      _entries.put(key, new Entry(identity, validUntilMs));
    }
  }

  void putRejected(String key, long nowMs) {
    if (_negativeTtlMs > 0) {
      _entries.put(key, new Entry(null, nowMs + _negativeTtlMs));
    }
  }

  static String key(String token) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
