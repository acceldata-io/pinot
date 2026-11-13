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
package org.apache.pinot.client.utils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import javax.net.ssl.SSLContext;
import org.apache.commons.configuration2.MapConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.pinot.common.config.TlsConfig;
import org.apache.pinot.common.utils.tls.TlsUtils;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ConnectionUtils {
  private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionUtils.class);

  public static final String INFO_HEADERS = "headers";
  public static final String PINOT_JAVA_TLS_PREFIX = "pinot.java_client.tls";
  public static final int APP_ID_MAX_CHARS = 256;

  private ConnectionUtils() {
  }

  public static Map<String, String> getHeadersFromProperties(Properties info) {
    return info.entrySet().stream().filter(entry -> entry.getKey().toString().startsWith(INFO_HEADERS + ".")).map(
            entry -> Pair.of(entry.getKey().toString().substring(INFO_HEADERS.length() + 1),
                entry.getValue().toString()))
        .collect(Collectors.toMap(Pair::getKey, Pair::getValue));
  }

  /// Connection property naming a class that supplies request headers each time a request is sent, e.g. a fresh
  /// OAuth 2.0 token: it must implement `Supplier<Map<String, String>>` and have a public no-argument constructor.
  /// Its headers are added to the fixed `headers.<name>` ones and win over them.
  public static final String HEADERS_SUPPLIER = "headersSupplier";

  /// The request headers of a connection: the fixed `headers.<name>` properties and, with [#HEADERS_SUPPLIER], the
  /// headers of that supplier, obtained again for every request.
  ///
  /// @throws IllegalArgumentException if the supplier class cannot be created
  public static Supplier<Map<String, String>> getHeadersSupplierFromProperties(Properties info) {
    Map<String, String> fixed = getHeadersFromProperties(info);
    String className = info.getProperty(HEADERS_SUPPLIER);
    if (className == null || className.trim().isEmpty()) {
      return () -> fixed;
    }
    return combine(fixed, instantiateHeadersSupplier(className.trim()));
  }

  /// Fixed headers plus the headers of a supplier, obtained again on every call; the supplier's win.
  public static Supplier<Map<String, String>> combine(@Nullable Map<String, String> fixed,
      @Nullable Supplier<Map<String, String>> dynamic) {
    Map<String, String> fixedCopy = fixed == null ? Map.of() : Map.copyOf(fixed);
    if (dynamic == null) {
      return () -> fixedCopy;
    }
    return () -> {
      Map<String, String> headers = new HashMap<>(fixedCopy);
      Map<String, String> supplied = dynamic.get();
      if (supplied != null) {
        headers.putAll(supplied);
      }
      return headers;
    };
  }

  @SuppressWarnings("unchecked")
  private static Supplier<Map<String, String>> instantiateHeadersSupplier(String className) {
    try {
      Object instance = Class.forName(className).getDeclaredConstructor().newInstance();
      if (!(instance instanceof Supplier)) {
        throw new IllegalArgumentException(HEADERS_SUPPLIER + " class " + className + " does not implement "
            + Supplier.class.getName());
      }
      return (Supplier<Map<String, String>>) instance;
    } catch (ReflectiveOperationException | LinkageError e) {
      throw new IllegalArgumentException("Cannot create the " + HEADERS_SUPPLIER + " class " + className, e);
    }
  }

  public static SSLContext getSSLContextFromProperties(Properties properties) {
    TlsConfig tlsConfig = TlsUtils.extractTlsConfig(
        new PinotConfiguration(new MapConfiguration(properties)), PINOT_JAVA_TLS_PREFIX);
    TlsUtils.installDefaultSSLSocketFactory(tlsConfig);
    return TlsUtils.getSslContext();
  }


  public static String getUserAgentVersionFromClassPath(String userAgentKey, @Nullable String appId) {
    Properties userAgentProperties = new Properties();
    try {
      userAgentProperties.load(ConnectionUtils.class.getClassLoader()
          .getResourceAsStream("version.properties"));
    } catch (IOException e) {
      LOGGER.warn("Unable to set user agent version");
    }
    String userAgentFromProperties = userAgentProperties.getProperty(userAgentKey, "unknown");
    if (StringUtils.isNotEmpty(appId)) {
      return appId.substring(0, Math.min(APP_ID_MAX_CHARS, appId.length())) + "-" + userAgentFromProperties;
    }
    return userAgentFromProperties;
  }
}
