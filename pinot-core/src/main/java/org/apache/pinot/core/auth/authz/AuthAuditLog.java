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
package org.apache.pinot.core.auth.authz;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.spi.utils.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/// Security audit of the authentication and authorization framework: one JSON line per event on the logger
/// `org.apache.pinot.auth.audit` (route it to its own file in the logging configuration). Never contains a credential.
///
/// Events (shared schema: `time`, `event`, `outcome`, `method`, `user`, `groups`, `serviceAccount`, `handler`,
/// `reason`, and for authorization `mode`, `resource`, `action`, `permission`, `accessType`):
/// - `authentication` / `failure`: every rejected credential, with the reason;
/// - `authentication` / `success`: the first use of each credential (its sign-in), not every request;
/// - `authorization` / `denied`, and `wouldDeny` in audit-only mode.
///
/// Also remembers recently authenticated credentials (by SHA-256) so that the request audit can name the verified
/// user and method (see [PinotAuthAuditTokenResolver]). Thread-safe.
public final class AuthAuditLog {
  public static final String LOGGER_NAME = "org.apache.pinot.auth.audit";
  private static final Logger AUDIT = LoggerFactory.getLogger(LOGGER_NAME);
  private static final int MAX_ENTRIES = 10_000;
  private static final long RECENT_MS = 5 * 60 * 1000L;

  /// Where events go: the audit logger, or a test's collector.
  private final Consumer<String> _sink;

  AuthAuditLog() {
    this(AUDIT::warn);
  }

  AuthAuditLog(Consumer<String> sink) {
    _sink = sink;
  }

  private final Map<String, Recent> _recent = Collections.synchronizedMap(new LinkedHashMap<String, Recent>(16, 0.75f,
      true) {
    @Override
    protected boolean removeEldestEntry(Map.Entry<String, Recent> eldest) {
      return size() > MAX_ENTRIES;
    }
  });

  private static final class Recent {
    final PinotPrincipal _principal;
    final long _untilMs;

    Recent(PinotPrincipal principal, long untilMs) {
      _principal = principal;
      _untilMs = untilMs;
    }
  }

  void authenticationSucceeded(PinotPrincipal principal, String authorizationHeader) {
    String key = key(authorizationHeader);
    long now = System.currentTimeMillis();
    Recent previous = _recent.put(key, new Recent(principal, now + RECENT_MS));
    if (previous == null) {
      ObjectNode event = event("authentication", "success", principal.getMethod());
      principal(event, principal);
      _sink.accept(event.toString());
    }
  }

  void authenticationFailed(AuthMethod method, String reason) {
    ObjectNode event = event("authentication", "failure", method);
    event.put("reason", reason);
    _sink.accept(event.toString());
  }

  void authorization(PinotPrincipal principal, AccessRequest request, String mode, String outcome, String reason) {
    ObjectNode event = event("authorization", outcome, principal.getMethod());
    principal(event, principal);
    event.put("mode", mode);
    event.put("resource", request.describeResource());
    if (request.getAction() != null) {
      event.put("action", request.getAction());
    }
    event.put("permission", request.getPermission().name());
    event.put("accessType", request.getAccessType());
    event.put("reason", reason);
    _sink.accept(event.toString());
  }

  /// The principal of a credential authenticated in the last minutes, for the request audit.
  @Nullable
  PinotPrincipal recentPrincipal(String authorizationHeader) {
    Recent recent = _recent.get(key(authorizationHeader));
    return recent != null && recent._untilMs > System.currentTimeMillis() ? recent._principal : null;
  }

  private static ObjectNode event(String event, String outcome, AuthMethod method) {
    ObjectNode node = JsonUtils.newObjectNode();
    node.put("time", Instant.now().toString());
    node.put("event", event);
    node.put("outcome", outcome);
    node.put("method", method.getConfigValue());
    return node;
  }

  private static void principal(ObjectNode event, PinotPrincipal principal) {
    event.put("user", principal.getUser());
    ArrayNode groups = event.putArray("groups");
    principal.getGroups().forEach(groups::add);
    event.put("serviceAccount", principal.isServiceAccount());
    Object handler = principal.getClaims().get("handler");
    if (handler != null) {
      event.put("handler", String.valueOf(handler));
    }
  }

  private static String key(String authorizationHeader) {
    try {
      return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
          .digest(authorizationHeader.trim().getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
