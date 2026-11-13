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

import java.io.File;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.pinot.common.auth.AuthConfig;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenSource;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.auth.AuthProvider;
import org.apache.pinot.spi.env.PinotConfiguration;


/// [AuthProvider] for Pinot's own calls between components on an OAuth 2.0 cluster: every outbound request carries
/// `Authorization: Bearer <token>`, with a token kept fresh by [CachingTokenSource]. Configure it in each outbound
/// namespace (`controller.broker.auth`, `controller.server.admin.auth`, `pinot.controller.segment.fetcher.auth`,
/// `pinot.broker.server.admin.auth`, `pinot.server.segment.fetcher.auth`, `pinot.server.segment.uploader.auth`,
/// `pinot.server.instance.auth`, `task.auth`, `pinot.minion.segment.fetcher.auth`):
/// ```
/// <namespace>.provider.class=org.apache.pinot.plugin.auth.oauth2.OAuthAuthProvider
/// <namespace>.source=client_credentials
/// <namespace>.token.url=https://idp.example.com/oauth2/token
/// <namespace>.client.id=pinot-service
/// <namespace>.client.secret=${PINOT_OAUTH_CLIENT_SECRET}
/// ```
/// - `source`: `client_credentials` (default, see [ClientCredentialsTokenSource]), `google_service_account` (see
///   [GoogleServiceAccountTokenSource]), `http` (see [HttpTokenSource]) or `java` (`class`, `jar.dir`: an
///   [OAuthTokenSource] from its own jars, loaded like a custom token handler)
/// - secrets: a source's secret alias (e.g. `client.secret`) is read from the namespace setting of that name, whose
///   value deployments inject with Pinot's dynamic configuration rather than writing it to disk
///
/// Namespaces with the same settings share one token per process, so a process makes one token request per refresh.
/// Thread-safe.
public class OAuthAuthProvider implements AuthProvider {
  private static final Map<Map<String, String>, CachingTokenSource> SOURCES = new ConcurrentHashMap<>();
  static final long INITIAL_BACKOFF_MS = 200;

  private final CachingTokenSource _source;

  public OAuthAuthProvider(AuthConfig authConfig) {
    Map<String, String> settings = new TreeMap<>();
    authConfig.getProperties().forEach((key, value) -> {
      if (!AuthConfig.PROVIDER_CLASS.equals(key) && value != null) {
        settings.put(key, value.toString());
      }
    });
    _source = SOURCES.computeIfAbsent(settings, OAuthAuthProvider::createSource);
  }

  @Override
  public Map<String, Object> getRequestHeaders() {
    Map<String, Object> headers = new HashMap<>();
    headers.put("Authorization", getTaskToken());
    return headers;
  }

  @Override
  public String getTaskToken() {
    return "Bearer " + _source.get();
  }

  /// The token was rejected by a peer (e.g. revoked at the provider): fetch a new one for the next request.
  @Override
  public boolean onUnauthorized() {
    return _source.invalidate();
  }

  private static CachingTokenSource createSource(Map<String, String> settings) {
    PinotConfiguration config = new PinotConfiguration(new HashMap<>(settings));
    String type = config.getProperty("source", ClientCredentialsTokenSource.TYPE).trim();
    String name = config.getProperty("name", type);
    OAuthTokenSource source;
    ClassLoader classLoader = OAuthAuthProvider.class.getClassLoader();
    switch (type) {
      case ClientCredentialsTokenSource.TYPE:
        source = new ClientCredentialsTokenSource();
        break;
      case GoogleServiceAccountTokenSource.TYPE:
        source = new GoogleServiceAccountTokenSource();
        break;
      case HttpTokenSource.TYPE:
        source = new HttpTokenSource();
        break;
      case OAuth2Authenticator.TYPE_JAVA: {
        String className = config.getProperty("class");
        if (className == null || className.trim().isEmpty()) {
          throw new IllegalArgumentException("Token source " + name + ": source java needs class");
        }
        File jarDir = new File(config.getProperty("jar.dir",
            new File(OAuth2Authenticator.defaultHandlersDir(), name).getPath()));
        classLoader = HandlerClassLoader.forDirectory(jarDir, classLoader);
        try {
          Object instance = Class.forName(className.trim(), true, classLoader).getDeclaredConstructor().newInstance();
          if (!(instance instanceof OAuthTokenSource)) {
            throw new IllegalStateException("Token source " + name + ": '" + className + "' does not implement "
                + OAuthTokenSource.class.getName());
          }
          source = (OAuthTokenSource) instance;
        } catch (ReflectiveOperationException | LinkageError e) {
          throw new IllegalStateException("Token source " + name + ": cannot create '" + className + "'", e);
        }
        break;
      }
      default:
        throw new IllegalArgumentException("Token source " + name + ": unsupported source '" + type + "'");
    }
    SecretResolver secrets = alias -> {
      String value = config.getProperty(alias);
      if (value == null || value.isEmpty()) {
        throw new IllegalArgumentException("Token source " + name + ": no secret under '" + alias + "'");
      }
      return value.toCharArray();
    };
    Thread thread = Thread.currentThread();
    ClassLoader previous = thread.getContextClassLoader();
    thread.setContextClassLoader(classLoader);
    try {
      source.init(new HandlerContext() {
        @Override
        public String getName() {
          return name;
        }

        @Override
        public PinotConfiguration getConfig() {
          return config;
        }

        @Override
        public SecretResolver getSecretResolver() {
          return secrets;
        }

        @Override
        public Clock getClock() {
          return Clock.systemUTC();
        }
      });
    } finally {
      thread.setContextClassLoader(previous);
    }
    return new CachingTokenSource(name, source, Clock.systemUTC(), INITIAL_BACKOFF_MS);
  }

  /// For tests: forget shared sources.
  static void clearSharedSources() {
    SOURCES.clear();
  }
}
