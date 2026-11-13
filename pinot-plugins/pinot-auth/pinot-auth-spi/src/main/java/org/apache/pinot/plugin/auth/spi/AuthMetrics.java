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

import java.util.concurrent.TimeUnit;
import org.apache.pinot.spi.metrics.PinotMetricUtils;
import org.apache.pinot.spi.metrics.PinotMetricsRegistry;
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

  private AuthMetrics() {
  }

  /// Counts one event.
  public static void mark(String name) {
    if (_disabled) {
      return;
    }
    try {
      PinotMetricsRegistry registry = PinotMetricUtils.getPinotMetricsRegistry();
      registry.newMeter(PinotMetricUtils.makePinotMetricName(AuthMetrics.class, PREFIX + name), "events",
          TimeUnit.SECONDS).mark();
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
      PinotMetricsRegistry registry = PinotMetricUtils.getPinotMetricsRegistry();
      registry.newTimer(PinotMetricUtils.makePinotMetricName(AuthMetrics.class, PREFIX + name), TimeUnit.MILLISECONDS,
          TimeUnit.SECONDS).update(durationMs, TimeUnit.MILLISECONDS);
    } catch (RuntimeException | LinkageError e) {
      disable(e);
    }
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
