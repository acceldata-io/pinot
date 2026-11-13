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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/// A configured text with `${name}` placeholders, rendered for one call with each value encoded for where it sits:
/// URL component, form field, JSON string content, or header value (line breaks refused). Placeholders are checked
/// against the allowed names when the template is created, so a typo fails the start, not a request. Immutable.
final class RequestTemplate {
  /// How placeholder values are encoded.
  enum Encoding {
    URL, FORM, JSON, HEADER, TEXT
  }

  private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");

  private final String _template;
  private final Encoding _encoding;

  /// @param allowed placeholder names that may appear; names starting with `secret:` are always allowed
  /// @throws IllegalArgumentException for an unknown placeholder
  RequestTemplate(String template, Encoding encoding, Set<String> allowed, String what) {
    _template = template;
    _encoding = encoding;
    for (String name : placeholders(template)) {
      if (!name.startsWith("secret:") && !allowed.contains(name)) {
        throw new IllegalArgumentException(what + ": unknown placeholder ${" + name + "}; allowed: " + allowed
            + " and ${secret:<alias>}");
      }
    }
  }

  static Set<String> placeholders(String template) {
    Set<String> names = new LinkedHashSet<>();
    Matcher matcher = PLACEHOLDER.matcher(template);
    while (matcher.find()) {
      names.add(matcher.group(1).trim());
    }
    return names;
  }

  /// Aliases of the `${secret:<alias>}` placeholders, so they can be resolved once at start.
  List<String> secretAliases() {
    List<String> aliases = new ArrayList<>();
    for (String name : placeholders(_template)) {
      if (name.startsWith("secret:")) {
        aliases.add(name.substring("secret:".length()).trim());
      }
    }
    return aliases;
  }

  /// @param values placeholder values; `secret:<alias>` entries included
  String render(Map<String, String> values) {
    Matcher matcher = PLACEHOLDER.matcher(_template);
    StringBuilder sb = new StringBuilder();
    while (matcher.find()) {
      String value = values.get(matcher.group(1).trim());
      matcher.appendReplacement(sb, Matcher.quoteReplacement(encode(value == null ? "" : value)));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  private String encode(String value) {
    switch (_encoding) {
      case URL:
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
      case FORM:
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
      case JSON:
        StringBuilder sb = new StringBuilder();
        for (char c : value.toCharArray()) {
          if (c == '"' || c == '\\') {
            sb.append('\\').append(c);
          } else if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
        }
        return sb.toString();
      case HEADER:
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
          throw new IllegalArgumentException("Line break in a header value");
        }
        return value;
      default:
        return value;
    }
  }

  static Set<String> names(String... names) {
    Set<String> set = new LinkedHashSet<>();
    Collections.addAll(set, names);
    return set;
  }
}
