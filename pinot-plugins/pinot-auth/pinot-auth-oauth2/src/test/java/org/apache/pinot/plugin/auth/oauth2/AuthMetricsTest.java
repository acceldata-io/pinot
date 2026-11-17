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

import java.util.Collections;
import java.util.concurrent.TimeUnit;
import org.apache.pinot.plugin.auth.spi.AuthMetrics;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.metrics.PinotMetricUtils;
import org.apache.pinot.spi.metrics.PinotMetricsRegistry;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotSame;


/// [AuthMetrics] records into Pinot's metrics registry, keeps its meters between calls, and follows a registry that
/// is initialised again (a role initialises Pinot's metrics after a token handler or source recorded its first metric).
public class AuthMetricsTest {

  private static long meter(PinotMetricsRegistry registry, String name) {
    return registry.newMeter(PinotMetricUtils.makePinotMetricName(AuthMetrics.class, AuthMetrics.PREFIX + name),
        "events", TimeUnit.SECONDS).count();
  }

  private static long timerCount(PinotMetricsRegistry registry, String name) {
    return registry.newTimer(PinotMetricUtils.makePinotMetricName(AuthMetrics.class, AuthMetrics.PREFIX + name),
        TimeUnit.MILLISECONDS, TimeUnit.SECONDS).count();
  }

  @Test
  public void testMetricsFollowTheCurrentRegistry() {
    PinotMetricsRegistry first = PinotMetricUtils.getPinotMetricsRegistry();
    long before = meter(first, "test.events");
    AuthMetrics.mark("test.events");
    AuthMetrics.mark("test.events");
    AuthMetrics.time("test.latencyMs", 3);
    assertEquals(meter(first, "test.events"), before + 2);
    assertEquals(timerCount(first, "test.latencyMs"), 1);

    // The role initialises Pinot's metrics: later events go to the new registry, not to the one cached before
    PinotMetricUtils.init(new PinotConfiguration(Collections.emptyMap()));
    PinotMetricsRegistry second = PinotMetricUtils.getPinotMetricsRegistry();
    assertNotSame(second, first);
    AuthMetrics.mark("test.events");
    assertEquals(meter(second, "test.events"), 1);
    assertEquals(meter(first, "test.events"), before + 2);
  }
}
