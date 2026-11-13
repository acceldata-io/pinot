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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.pinot.plugin.auth.spi.AccessToken;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenSource;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Google ID tokens for Pinot's own calls, from a Google service account: a JWT signed with the service account key
/// (RS256) is exchanged at Google's token endpoint for an ID token whose audience is `target.audience` (the OAuth
/// client id Pinot's `google` handler accepts). Google ID tokens live one hour.
///
/// Settings: `credentials.file` (service account key file in JSON, readable only by the Pinot user),
/// `target.audience` (required), `token.url` (default: the key file's `token_uri`), `http.timeout.ms` (default 5000).
/// Thread-safe after [#init].
public class GoogleServiceAccountTokenSource implements OAuthTokenSource {
  public static final String TYPE = "google_service_account";
  static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  static final String DEFAULT_TOKEN_URL = "https://oauth2.googleapis.com/token";

  private String _name;
  private HandlerContext _context;
  private ProviderHttp _http;
  private String _clientEmail;
  private RSASSASigner _signer;
  private JWSHeader _header;
  private String _tokenUrl;
  private String _audience;

  @Override
  public void init(HandlerContext context) {
    PinotConfiguration config = context.getConfig();
    _name = context.getName();
    _context = context;
    _http = new ProviderHttp(config.getProperty("http.timeout.ms", 5000L), ProviderHttp.DEFAULT_MAX_RESPONSE_BYTES);
    String file = config.getProperty("credentials.file");
    _audience = config.getProperty("target.audience");
    if (file == null || file.trim().isEmpty() || _audience == null || _audience.trim().isEmpty()) {
      throw new IllegalArgumentException(
          "Token source " + _name + ": credentials.file and target.audience are required");
    }
    _audience = _audience.trim();
    Map<String, Object> key;
    try {
      key = JSONObjectUtils.parse(new String(Files.readAllBytes(Paths.get(file.trim())), StandardCharsets.UTF_8));
    } catch (IOException | ParseException e) {
      throw new IllegalArgumentException("Token source " + _name + ": cannot read the service account key file", e);
    }
    Object email = key.get("client_email");
    Object privateKey = key.get("private_key");
    if (!(email instanceof String) || !(privateKey instanceof String)) {
      throw new IllegalArgumentException("Token source " + _name + ": the key file has no client_email / private_key");
    }
    _clientEmail = (String) email;
    try {
      // Service account keys are PKCS#8 PEM, which the JDK reads without extra libraries
      String base64 = ((String) privateKey).replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
      PrivateKey rsaKey = KeyFactory.getInstance("RSA")
          .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
      _signer = new RSASSASigner(rsaKey);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new IllegalArgumentException("Token source " + _name + ": the key file's private_key is not an RSA key", e);
    }
    JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256);
    if (key.get("private_key_id") instanceof String) {
      header.keyID((String) key.get("private_key_id"));
    }
    _header = header.build();
    String tokenUrl = config.getProperty("token.url");
    _tokenUrl = tokenUrl != null && !tokenUrl.trim().isEmpty() ? tokenUrl.trim()
        : key.get("token_uri") instanceof String ? (String) key.get("token_uri") : DEFAULT_TOKEN_URL;
  }

  @Override
  public AccessToken fetch() {
    Instant now = _context.getClock().instant();
    SignedJWT assertion = new SignedJWT(_header, new JWTClaimsSet.Builder().issuer(_clientEmail).subject(_clientEmail)
        .audience(_tokenUrl).issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(3600)))
        .claim("target_audience", _audience).build());
    try {
      assertion.sign(_signer);
    } catch (JOSEException e) {
      throw new IllegalStateException("Token source " + _name + ": cannot sign the assertion", e);
    }
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", GRANT_TYPE);
    form.put("assertion", assertion.serialize());
    ProviderHttp.Answer answer;
    try {
      answer = _http.postForm(_tokenUrl, form, Map.of());
    } catch (IOException e) {
      throw new IllegalStateException("Token source " + _name + ": cannot reach the token endpoint", e);
    }
    if (!answer.isOk()) {
      throw new IllegalStateException("Token source " + _name + ": token endpoint answered " + answer._status);
    }
    try {
      Object idToken = JSONObjectUtils.parse(answer._body).get("id_token");
      if (!(idToken instanceof String)) {
        throw new IllegalStateException("Token source " + _name + ": no id_token in the answer");
      }
      Date exp = SignedJWT.parse((String) idToken).getJWTClaimsSet().getExpirationTime();
      return new AccessToken((String) idToken, exp != null ? exp.toInstant() : now.plusSeconds(3600));
    } catch (ParseException e) {
      throw new IllegalStateException("Token source " + _name + ": the answer is not a JSON object with an ID token");
    }
  }
}
