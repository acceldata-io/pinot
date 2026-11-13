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
package org.apache.pinot.plugin.auth.samples.support;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;


/// Reads fields out of parsed JSON (see [Json]) by dotted path, e.g. `data.user.id` or `realm_access.roles`. This is
/// how the samples map a provider's response or token claims onto Pinot's user, groups and scopes; the paths come
/// from configuration so one handler fits differently shaped providers. Stateless and thread-safe.
public final class JsonMapping {
  private JsonMapping() {
  }

  /// @return the value at the path, or `null` when any segment is missing or not an object
  @Nullable
  public static Object get(Map<String, Object> root, String path) {
    Object current = root;
    for (String segment : path.split("\\.")) {
      if (!(current instanceof Map)) {
        return null;
      }
      current = ((Map<?, ?>) current).get(segment);
    }
    return current;
  }

  /// @return the value at the path as a string (numbers and booleans converted), or `null` if missing or not a scalar
  @Nullable
  public static String getString(Map<String, Object> root, String path) {
    Object value = get(root, path);
    if (value instanceof String) {
      String s = (String) value;
      return s.isEmpty() ? null : s;
    }
    if (value instanceof Number || value instanceof Boolean) {
      return String.valueOf(value);
    }
    return null;
  }

  /// @return the value at the path as a long (numeric strings accepted), or `null` if missing or not a number
  @Nullable
  public static Long getLong(Map<String, Object> root, String path) {
    Object value = get(root, path);
    if (value instanceof Number) {
      return ((Number) value).longValue();
    }
    if (value instanceof String) {
      try {
        return Long.parseLong(((String) value).trim());
      } catch (NumberFormatException e) {
        return null;
      }
    }
    return null;
  }

  /// A set of strings from a JSON array, or from a string split on spaces and commas (OAuth `scope` is a
  /// space-separated string; some providers send groups as a comma-separated string).
  ///
  /// @return the values, empty when the path is missing
  public static Set<String> getStrings(Map<String, Object> root, String path) {
    Object value = get(root, path);
    if (value == null) {
      return Collections.emptySet();
    }
    Set<String> result = new LinkedHashSet<>();
    if (value instanceof Collection) {
      for (Object item : (Collection<?>) value) {
        if (item instanceof String || item instanceof Number) {
          String s = String.valueOf(item).trim();
          if (!s.isEmpty()) {
            result.add(s);
          }
        }
      }
    } else if (value instanceof String) {
      for (String s : ((String) value).split("[\\s,]+")) {
        if (!s.isEmpty()) {
          result.add(s);
        }
      }
    }
    return result;
  }
}
