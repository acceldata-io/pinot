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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/// A small JSON reader, so the samples need nothing beyond the JDK and the SPI. Objects become `Map<String, Object>`
/// (insertion order kept), arrays `List<Object>`, numbers `Long` when integral and `Double` otherwise, plus `String`,
/// `Boolean` and `null`. Rejects trailing content and nesting deeper than 64 levels. If your handler bundles Jackson
/// or Gson in its own jar, use that instead. Stateless and thread-safe.
public final class Json {
  private static final int MAX_DEPTH = 64;

  private final String _text;
  private int _pos;

  private Json(String text) {
    _text = text;
  }

  /// @throws IllegalArgumentException if the text is not valid JSON
  public static Object parse(String text) {
    Json json = new Json(text);
    json.skipWhitespace();
    Object value = json.readValue(0);
    json.skipWhitespace();
    if (json._pos != text.length()) {
      throw json.error("Unexpected content after the JSON value");
    }
    return value;
  }

  /// @throws IllegalArgumentException if the text is not a JSON object
  @SuppressWarnings("unchecked")
  public static Map<String, Object> parseObject(String text) {
    Object value = parse(text);
    if (!(value instanceof Map)) {
      throw new IllegalArgumentException("Expected a JSON object");
    }
    return (Map<String, Object>) value;
  }

  private Object readValue(int depth) {
    if (depth > MAX_DEPTH) {
      throw error("JSON nested too deeply");
    }
    if (_pos >= _text.length()) {
      throw error("Unexpected end of JSON");
    }
    char c = _text.charAt(_pos);
    switch (c) {
      case '{':
        return readObject(depth);
      case '[':
        return readArray(depth);
      case '"':
        return readString();
      case 't':
        expectWord("true");
        return Boolean.TRUE;
      case 'f':
        expectWord("false");
        return Boolean.FALSE;
      case 'n':
        expectWord("null");
        return null;
      default:
        if (c == '-' || (c >= '0' && c <= '9')) {
          return readNumber();
        }
        throw error("Unexpected character '" + c + "'");
    }
  }

  private Map<String, Object> readObject(int depth) {
    Map<String, Object> map = new LinkedHashMap<>();
    _pos++;
    skipWhitespace();
    if (peek() == '}') {
      _pos++;
      return map;
    }
    while (true) {
      skipWhitespace();
      if (peek() != '"') {
        throw error("Expected a field name");
      }
      String key = readString();
      skipWhitespace();
      expect(':');
      skipWhitespace();
      map.put(key, readValue(depth + 1));
      skipWhitespace();
      char c = next();
      if (c == '}') {
        return map;
      }
      if (c != ',') {
        throw error("Expected ',' or '}'");
      }
    }
  }

  private List<Object> readArray(int depth) {
    List<Object> list = new ArrayList<>();
    _pos++;
    skipWhitespace();
    if (peek() == ']') {
      _pos++;
      return list;
    }
    while (true) {
      skipWhitespace();
      list.add(readValue(depth + 1));
      skipWhitespace();
      char c = next();
      if (c == ']') {
        return list;
      }
      if (c != ',') {
        throw error("Expected ',' or ']'");
      }
    }
  }

  private String readString() {
    expect('"');
    StringBuilder sb = new StringBuilder();
    while (true) {
      char c = next();
      if (c == '"') {
        return sb.toString();
      }
      if (c < 0x20) {
        throw error("Control character in string");
      }
      if (c != '\\') {
        sb.append(c);
        continue;
      }
      char escape = next();
      switch (escape) {
        case '"':
        case '\\':
        case '/':
          sb.append(escape);
          break;
        case 'b':
          sb.append('\b');
          break;
        case 'f':
          sb.append('\f');
          break;
        case 'n':
          sb.append('\n');
          break;
        case 'r':
          sb.append('\r');
          break;
        case 't':
          sb.append('\t');
          break;
        case 'u':
          if (_pos + 4 > _text.length()) {
            throw error("Bad unicode escape");
          }
          try {
            sb.append((char) Integer.parseInt(_text.substring(_pos, _pos + 4), 16));
          } catch (NumberFormatException e) {
            throw error("Bad unicode escape");
          }
          _pos += 4;
          break;
        default:
          throw error("Bad escape '\\" + escape + "'");
      }
    }
  }

  private Object readNumber() {
    int start = _pos;
    boolean integral = true;
    while (_pos < _text.length()) {
      char c = _text.charAt(_pos);
      if (c == '.' || c == 'e' || c == 'E') {
        integral = false;
      } else if (!(c == '-' || c == '+' || (c >= '0' && c <= '9'))) {
        break;
      }
      _pos++;
    }
    String number = _text.substring(start, _pos);
    try {
      if (integral) {
        try {
          return Long.parseLong(number);
        } catch (NumberFormatException e) {
          // Too large for a long
          return Double.parseDouble(number);
        }
      }
      return Double.parseDouble(number);
    } catch (NumberFormatException e) {
      throw error("Bad number '" + number + "'");
    }
  }

  private void expectWord(String word) {
    if (!_text.startsWith(word, _pos)) {
      throw error("Expected '" + word + "'");
    }
    _pos += word.length();
  }

  private void expect(char c) {
    if (next() != c) {
      throw error("Expected '" + c + "'");
    }
  }

  private char peek() {
    if (_pos >= _text.length()) {
      throw error("Unexpected end of JSON");
    }
    return _text.charAt(_pos);
  }

  private char next() {
    char c = peek();
    _pos++;
    return c;
  }

  private void skipWhitespace() {
    while (_pos < _text.length() && Character.isWhitespace(_text.charAt(_pos))) {
      _pos++;
    }
  }

  private IllegalArgumentException error(String message) {
    // Never include the text itself: it may be a token or a provider response
    return new IllegalArgumentException(message + " at offset " + _pos);
  }
}
