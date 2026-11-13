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

import java.util.Objects;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Resolves a secret alias from the component configuration: alias `a.b` is read from `pinot.auth.secrets.a.b`.
/// Deployments keep the value itself out of configuration files with Pinot's dynamic configuration (for example
/// `dynamic.env.config`, filled from a credential store at start), so only the reference is written to disk.
/// Thread-safe.
public final class ConfigSecretResolver implements SecretResolver {
  public static final String SECRETS_PREFIX = AuthMethodSelector.CONFIG_PREFIX + ".secrets";

  private final PinotConfiguration _secrets;

  public ConfigSecretResolver(PinotConfiguration componentConfig) {
    _secrets = Objects.requireNonNull(componentConfig, "componentConfig").subset(SECRETS_PREFIX);
  }

  @Override
  public char[] resolve(String alias) {
    String value = _secrets.getProperty(alias);
    if (value == null) {
      throw new IllegalArgumentException("Unknown secret alias '" + alias + "': set " + SECRETS_PREFIX + "." + alias);
    }
    return value.toCharArray();
  }
}
