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
package org.apache.pinot.plugin.auth.spi;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.apache.pinot.spi.metrics.PinotMeter;
import org.apache.pinot.spi.metrics.PinotMetricUtils;
import org.apache.pinot.spi.metrics.PinotMetricsRegistry;
import org.apache.pinot.spi.metrics.PinotTimer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Metrics of authentication, in Pinot's metrics registry under `pinot.auth.`, e.g.
/// `pinot.auth.oauth2.handler.<name>.accepted`. Thread-safe.
///
/// Per token handler: `accepted`, `rejected`, `unavailable` (provider failure or timeout), `cacheHits`,
/// `providerLatencyMs` (timer of the calls that reached the handler), `breakerOpened`. Per outbound token source:
/// `oauth2.outbound.<name>.refreshes` and `refreshFailures`. Per method: `<method>.requestsRejected.missing` and
/// `<method>.requestsRejected.wrongScheme`.
///
/// Metrics never affect authentication: if the registry is not available (e.g. no metrics implementation on the
/// classpath), recording is switched off after one warning.
public final class AuthMetrics {
  public static final String PREFIX = "pinot.auth.";
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthMetrics.class);
  private static volatile boolean _disabled;
  private static volatile Metrics _metrics;

  /// The meters and timers created in one registry. Metrics are on the request path, so each is looked up in the
  /// registry once; a new registry (the role initialising Pinot's metrics after a metric was first recorded) starts a
  /// new set.
  private static final class Metrics {
    final PinotMetricsRegistry _registry;
    final Map<String, PinotMeter> _meters = new ConcurrentHashMap<>();
    final Map<String, PinotTimer> _timers = new ConcurrentHashMap<>();

    Metrics(PinotMetricsRegistry registry) {
      _registry = registry;
    }
  }

  private AuthMetrics() {
  }

  /// Counts one event.
  public static void mark(String name) {
    if (_disabled) {
      return;
    }
    try {
      Metrics metrics = metrics();
      metrics._meters.computeIfAbsent(name, n -> metrics._registry.newMeter(
          PinotMetricUtils.makePinotMetricName(AuthMetrics.class, PREFIX + n), "events", TimeUnit.SECONDS)).mark();
    } catch (RuntimeException | LinkageError e) {
      disable(e);
    }
  }

  /// Records a duration.
  public static void time(String name, long durationMs) {
    if (_disabled) {
      return;
    }
    try {
      Metrics metrics = metrics();
      metrics._timers.computeIfAbsent(name, n -> metrics._registry.newTimer(
          PinotMetricUtils.makePinotMetricName(AuthMetrics.class, PREFIX + n), TimeUnit.MILLISECONDS, TimeUnit.SECONDS))
          .update(durationMs, TimeUnit.MILLISECONDS);
    } catch (RuntimeException | LinkageError e) {
      disable(e);
    }
  }

  /// The metrics of the current registry, without locking once Pinot's metrics are initialised.
  private static Metrics metrics() {
    PinotMetricsRegistry registry = PinotMetricUtils.getPinotMetricsRegistryIfInitialized();
    if (registry == null) {
      registry = PinotMetricUtils.getPinotMetricsRegistry();  // initialises Pinot's metrics with defaults, once
    }
    Metrics metrics = _metrics;
    if (metrics == null || metrics._registry != registry) {
      metrics = new Metrics(registry);
      _metrics = metrics;
    }
    return metrics;
  }

  private static void disable(Throwable e) {
    if (!_disabled) {
      _disabled = true;
      LOGGER.warn("Authentication metrics are not recorded: the metrics registry is not available", e);
    }
  }

  /// Metric name prefix of a token handler of the OAuth 2.0 method.
  public static String handler(String name) {
    return "oauth2.handler." + name + ".";
  }
}
