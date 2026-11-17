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
package org.apache.pinot.plugin.auth.ldap;

import javax.annotation.Nullable;

/// Escaping of user input before it enters an LDAP filter or a distinguished name, so a user name cannot change the
/// meaning of a search (LDAP injection, e.g. `*)(uid=*`) or of a bind DN. Stateless and thread-safe.
final class LdapEscaping {
  private LdapEscaping() {
  }

  /// Escapes a value for an LDAP search filter (RFC 4515 section 3): `*`, `(`, `)`, `\` and NUL become `\2a`,
  /// `\28`, `\29`, `\5c`, `\00`; other characters, including non-ASCII ones, are kept (JNDI sends them as UTF-8).
  static String filterValue(String value) {
    StringBuilder out = new StringBuilder(value.length() + 8);
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '*':
          out.append("\\2a");
          break;
        case '(':
          out.append("\\28");
          break;
        case ')':
          out.append("\\29");
          break;
        case '\\':
          out.append("\\5c");
          break;
        case '\u0000':
          out.append("\\00");
          break;
        default:
          out.append(c);
          break;
      }
    }
    return out.toString();
  }

  /// Escapes a value for one attribute value of a distinguished name (RFC 4514 section 2.4): `,`, `+`, `"`, `\`,
  /// `<`, `>`, `;` and `=` are escaped with a backslash, as are a leading space or `#` and a trailing space; NUL
  /// becomes `\00`.
  static String dnValue(String value) {
    StringBuilder out = new StringBuilder(value.length() + 8);
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case ',':
        case '+':
        case '"':
        case '\\':
        case '<':
        case '>':
        case ';':
        case '=':
          out.append('\\').append(c);
          break;
        case '\u0000':
          out.append("\\00");
          break;
        case ' ':
          out.append(i == 0 || i == value.length() - 1 ? "\\ " : " ");
          break;
        case '#':
          out.append(i == 0 ? "\\#" : "#");
          break;
        default:
          out.append(c);
          break;
      }
    }
    return out.toString();
  }

  /// Replaces `{0}` (and `{1}` when given) in a filter or DN template with already escaped values.
  static String format(String template, String arg0, @Nullable String arg1) {
    String result = template.replace("{0}", arg0);
    return arg1 == null ? result : result.replace("{1}", arg1);
  }
}
