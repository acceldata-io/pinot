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

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.pinot.plugin.auth.spi.OAuthTokenSource;


/// Pinot service tokens for processes outside Pinot that call Pinot as the Pinot service does, e.g. Ranger Admin's
/// Test Connection and resource lookup on an OAuth 2.0 cluster. The settings are those of [OAuthAuthProvider]
/// (`source`, `token.url`, `client.id`, the source's own settings and its secret under its alias, e.g.
/// `client.secret`), so every token source Pinot supports gives the same token there. One token per call: no shared
/// cache and no background refresh thread, which a long-running host process would otherwise keep per settings.
///
/// Uses only JDK types in its signature, so that callers can invoke it through reflection from their own class
/// loader without Pinot's classes on their class path. Callers on a Java runtime older than Pinot's run [#main] in a
/// child process instead.
public final class ServiceTokens {
  private ServiceTokens() {
  }

  /// @return a fresh access token (without a scheme)
  /// @throws IllegalArgumentException if the settings are incomplete
  /// @throws IllegalStateException if the source cannot be created or the provider cannot be reached
  public static String fetch(Map<String, String> settings) {
    try (OAuthTokenSource source = OAuthAuthProvider.newTokenSource(settings)) {
      return source.fetch().getToken();
    }
  }

  /// For callers on an older Java runtime: reads the settings from standard input (Java properties format, so that
  /// secrets never appear on a command line) and prints the token on standard output. Exit status 1 and the reason
  /// on standard error when no token can be fetched.
  public static void main(String[] args)
      throws IOException {
    Properties properties = new Properties();
    properties.load(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    Map<String, String> settings = new HashMap<>();
    properties.stringPropertyNames().forEach(name -> settings.put(name, properties.getProperty(name)));
    try {
      System.out.println(fetch(settings));
    } catch (RuntimeException e) {
      System.err.println(e.getMessage());
      System.exit(1);
    }
  }
}
