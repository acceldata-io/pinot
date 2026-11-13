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

import java.util.HashMap;
import java.util.Map;
import org.apache.pinot.spi.env.PinotConfiguration;


/// `type=google`: Google ID tokens (for example from Google Sign-In or a service account) through the jwt handler with
/// Google's fixed settings. Settings: `client.ids` (required, comma-separated OAuth client ids = accepted audiences),
/// `hosted.domain` (optional Google Workspace domain, checked against `hd`), `user.claim` (default `email`). Google
/// access tokens (`ya29.`) are opaque and need Google's token-info endpoint, not this preset.
final class GoogleHandlerPreset {
  static final String TYPE = "google";
  static final String ISSUER = "https://accounts.google.com";
  static final String JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

  private GoogleHandlerPreset() {
  }

  /// The jwt handler settings for a google handler.
  static PinotConfiguration toJwtConfig(PinotConfiguration google) {
    String clientIds = google.getProperty("client.ids");
    if (clientIds == null || clientIds.trim().isEmpty()) {
      throw new IllegalArgumentException("google handler needs client.ids (the OAuth client ids allowed as audience)");
    }
    Map<String, Object> jwt = new HashMap<>();
    jwt.put("issuer", ISSUER);
    jwt.put("jwks.url", google.getProperty("jwks.url", JWKS_URL));
    jwt.put("audiences", clientIds.trim());
    jwt.put("algorithms", "RS256");
    jwt.put("accept.id.tokens", "true");
    jwt.put("user.claim", google.getProperty("user.claim", "email"));
    String domain = google.getProperty("hosted.domain");
    jwt.put("required.claims", "email_verified=true"
        + (domain == null || domain.trim().isEmpty() ? "" : ",hd=" + domain.trim()));
    jwt.put("clock.skew.seconds", google.getProperty("clock.skew.seconds", "60"));
    return new PinotConfiguration(jwt);
  }
}
