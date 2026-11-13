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
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/// Loads custom token handlers from their own jars, isolated from Pinot's classpath. The parent exposes only the JDK,
/// the authentication SPI and the few Pinot types the SPI uses, so a handler builds against the SPI alone and brings
/// its other dependencies in its own jars, without clashing with Pinot's.
final class HandlerClassLoader extends URLClassLoader {
  /// Packages a handler may use from Pinot's classpath.
  static final List<String> SHARED_PREFIXES = Arrays.asList("java.", "javax.", "jdk.", "sun.", "com.sun.",
      "org.apache.pinot.plugin.auth.spi.", "org.apache.pinot.spi.env.", "org.slf4j.");

  private HandlerClassLoader(URL[] jars, ClassLoader shared) {
    super(jars, new SharedOnly(shared));
  }

  /// @param dir directory with the handler jar and its dependencies
  /// @throws IllegalArgumentException if the directory holds no jar
  static HandlerClassLoader forDirectory(File dir, ClassLoader shared) {
    File[] files = dir.listFiles((d, name) -> name.endsWith(".jar"));
    if (files == null || files.length == 0) {
      throw new IllegalArgumentException("No handler jars in " + dir.getAbsolutePath());
    }
    Arrays.sort(files);
    List<URL> urls = new ArrayList<>();
    for (File file : files) {
      try {
        urls.add(file.toURI().toURL());
      } catch (MalformedURLException e) {
        throw new IllegalArgumentException("Bad handler jar path " + file, e);
      }
    }
    return new HandlerClassLoader(urls.toArray(new URL[0]), shared);
  }

  /// Delegates only the shared packages to Pinot's class loader; everything else must come from the handler jars.
  private static final class SharedOnly extends ClassLoader {
    private final ClassLoader _shared;

    SharedOnly(ClassLoader shared) {
      super(null);
      _shared = shared;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve)
        throws ClassNotFoundException {
      for (String prefix : SHARED_PREFIXES) {
        if (name.startsWith(prefix)) {
          return _shared.loadClass(name);
        }
      }
      throw new ClassNotFoundException(name + " is not available to token handlers; bundle it in the handler jar");
    }

    @Override
    public URL getResource(String name) {
      return name.startsWith("java/") ? _shared.getResource(name) : null;
    }
  }
}
