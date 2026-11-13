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
package org.apache.pinot.plugin.auth.samples;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Handler context for the sample tests: given settings, a fixed map of secrets and a fixed clock.
final class TestContext implements HandlerContext {
  private final PinotConfiguration _config;
  private final Map<String, String> _secrets;
  private final Clock _clock;

  TestContext(Map<String, Object> settings, Map<String, String> secrets, Instant now) {
    _config = new PinotConfiguration(settings);
    _secrets = secrets;
    _clock = Clock.fixed(now, ZoneOffset.UTC);
  }

  @Override
  public String getName() {
    return "idm";
  }

  @Override
  public PinotConfiguration getConfig() {
    return _config;
  }

  @Override
  public SecretResolver getSecretResolver() {
    return alias -> {
      String secret = _secrets.get(alias);
      if (secret == null) {
        throw new IllegalArgumentException("Unknown alias " + alias);
      }
      return secret.toCharArray();
    };
  }

  @Override
  public Clock getClock() {
    return _clock;
  }
}
