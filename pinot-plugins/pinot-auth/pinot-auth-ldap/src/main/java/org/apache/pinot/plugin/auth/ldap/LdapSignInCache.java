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
package org.apache.pinot.plugin.auth.ldap;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.annotation.Nullable;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Sign-in results of the `ldap` method, so the directory is not asked on every request and client retry loops cannot
/// lock a directory account:
/// - Success cache: a sign-in is answered from the cache while the same password is presented within
///   `cache.ttl.seconds` (default 300) after the directory accepted it, `cache.service.ttl.seconds` (default 3600) for
///   `service.users`, so Pinot's own calls ride through short directory outages. A different password always goes to
///   the directory. At most `cache.max.entries` (default 10000) users are kept, least recently used dropped. Passwords
///   are kept only as salted SHA-256 digests.
/// - Failure cache: the same wrong password presented again within `failure.cache.seconds` (default 30) is refused
///   without a bind.
/// - Throttle: after `failure.max.attempts` (default 5) wrong passwords for a user within `failure.window.seconds`
///   (default 60), further sign-ins of that user are refused without a bind until the window has passed. Keep the
///   attempts below the directory's lockout threshold.
/// Users are keyed by the lower-cased login name. Results of an unavailable directory are never cached. Thread-safe.
final class LdapSignInCache {
  private final Clock _clock;
  private final long _ttlMs;
  private final long _serviceTtlMs;
  private final long _failureTtlMs;
  private final int _maxAttempts;
  private final long _windowMs;
  private final Map<String, Success> _successes;
  private final Map<String, Failures> _failures;
  private final SecureRandom _random = new SecureRandom();

  private static final class Success {
    final byte[] _salt;
    final byte[] _digest;
    final LdapDirectory.User _user;
    final long _validUntilMs;

    Success(byte[] salt, byte[] digest, LdapDirectory.User user, long validUntilMs) {
      _salt = salt;
      _digest = digest;
      _user = user;
      _validUntilMs = validUntilMs;
    }
  }

  private static final class Failures {
    final Deque<Long> _times = new ArrayDeque<>();
    byte[] _lastSalt;
    byte[] _lastDigest;
    long _lastUntilMs;
  }

  /// The outcome of a cache lookup: the verdict, and the user when answered from the cache.
  static final class Lookup {
    final Verdict _verdict;
    @Nullable
    final LdapDirectory.User _user;

    Lookup(Verdict verdict, @Nullable LdapDirectory.User user) {
      _verdict = verdict;
      _user = user;
    }
  }

  enum Verdict {
    /// Answered from the success cache.
    CACHED,
    /// The same wrong password again within the failure cache period.
    REPEATED_FAILURE,
    /// Too many wrong passwords for this user recently.
    THROTTLED,
    /// Ask the directory.
    ASK
  }

  LdapSignInCache(PinotConfiguration config, Clock clock) {
    _clock = clock;
    _ttlMs = config.getProperty("cache.ttl.seconds", 300L) * 1000;
    _serviceTtlMs = config.getProperty("cache.service.ttl.seconds", 3600L) * 1000;
    _failureTtlMs = config.getProperty("failure.cache.seconds", 30L) * 1000;
    _maxAttempts = config.getProperty("failure.max.attempts", 5);
    _windowMs = config.getProperty("failure.window.seconds", 60L) * 1000;
    int maxEntries = config.getProperty("cache.max.entries", 10000);
    if (_maxAttempts < 1 || maxEntries < 1) {
      throw new IllegalArgumentException("LDAP: failure.max.attempts and cache.max.entries must be at least 1");
    }
    _successes = lru(maxEntries);
    _failures = lru(maxEntries);
  }

  private static <V> Map<String, V> lru(int maxEntries) {
    return new LinkedHashMap<String, V>(16, 0.75f, true) {
      @Override
      protected boolean removeEldestEntry(Map.Entry<String, V> eldest) {
        return size() > maxEntries;
      }
    };
  }

  /// Whether the sign-in can be answered without the directory.
  synchronized Lookup lookup(String login, char[] password) {
    String key = key(login);
    long now = _clock.millis();
    Success success = _successes.get(key);
    if (success != null) {
      if (success._validUntilMs > now && MessageDigest.isEqual(success._digest, digest(success._salt, password))) {
        return new Lookup(Verdict.CACHED, success._user);
      }
      if (success._validUntilMs <= now) {
        _successes.remove(key);
      }
    }
    Failures failures = _failures.get(key);
    if (failures != null) {
      if (failures._lastUntilMs > now && MessageDigest.isEqual(failures._lastDigest,
          digest(failures._lastSalt, password))) {
        return new Lookup(Verdict.REPEATED_FAILURE, null);
      }
      expire(failures, now);
      if (failures._times.size() >= _maxAttempts) {
        return new Lookup(Verdict.THROTTLED, null);
      }
    }
    return new Lookup(Verdict.ASK, null);
  }

  /// The directory accepted the password.
  synchronized void accepted(String login, char[] password, LdapDirectory.User user, boolean serviceAccount) {
    String key = key(login);
    byte[] salt = salt();
    _successes.put(key, new Success(salt, digest(salt, password), user,
        _clock.millis() + (serviceAccount ? _serviceTtlMs : _ttlMs)));
    _failures.remove(key);
  }

  /// The directory refused the password.
  synchronized void refused(String login, char[] password) {
    String key = key(login);
    long now = _clock.millis();
    _successes.remove(key);
    Failures failures = _failures.computeIfAbsent(key, k -> new Failures());
    expire(failures, now);
    failures._times.addLast(now);
    failures._lastSalt = salt();
    failures._lastDigest = digest(failures._lastSalt, password);
    failures._lastUntilMs = now + _failureTtlMs;
  }

  private void expire(Failures failures, long now) {
    while (!failures._times.isEmpty() && failures._times.peekFirst() <= now - _windowMs) {
      failures._times.removeFirst();
    }
  }

  private static String key(String login) {
    return login.trim().toLowerCase(Locale.ROOT);
  }

  private byte[] salt() {
    byte[] salt = new byte[16];
    _random.nextBytes(salt);
    return salt;
  }

  private static byte[] digest(byte[] salt, char[] password) {
    ByteBuffer bytes = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(salt);
      digest.update(bytes);
      return digest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    } finally {
      if (bytes.hasArray()) {
        Arrays.fill(bytes.array(), (byte) 0);
      }
    }
  }
}
