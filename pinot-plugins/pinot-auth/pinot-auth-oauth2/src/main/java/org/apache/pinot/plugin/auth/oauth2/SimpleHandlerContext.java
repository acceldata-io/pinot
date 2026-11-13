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
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;


/// [HandlerContext] for handlers created by [OAuth2Authenticator].
final class SimpleHandlerContext implements HandlerContext {
  private final String _name;
  private final PinotConfiguration _config;
  private final SecretResolver _secretResolver;

  SimpleHandlerContext(String name, PinotConfiguration config, SecretResolver secretResolver) {
    _name = name;
    _config = config;
    _secretResolver = secretResolver;
  }

  @Override
  public String getName() {
    return _name;
  }

  @Override
  public PinotConfiguration getConfig() {
    return _config;
  }

  @Override
  public SecretResolver getSecretResolver() {
    return _secretResolver;
  }

  @Override
  public Clock getClock() {
    return Clock.systemUTC();
  }
}
