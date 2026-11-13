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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


/// Minimal handling of compact JWTs signed with an HMAC key (HS256 / HS384 / HS512), enough for a provider that
/// shares a secret with its resource servers. For RSA / EC keys published as JWKS use the built-in `jwt` handler
/// instead of extending this. Stateless and thread-safe.
public final class Jwts {
  private Jwts() {
  }

  /// A JWT split into its parts. The claims are not trusted until [#verifyHmac] succeeds.
  public static final class Parsed {
    private final Map<String, Object> _header;
    private final Map<String, Object> _claims;
    private final String _signingInput;
    private final byte[] _signature;

    Parsed(Map<String, Object> header, Map<String, Object> claims, String signingInput, byte[] signature) {
      _header = header;
      _claims = claims;
      _signingInput = signingInput;
      _signature = signature;
    }

    public Map<String, Object> getHeader() {
      return _header;
    }

    public Map<String, Object> getClaims() {
      return _claims;
    }

    @Nullable
    public String getAlgorithm() {
      return JsonMapping.getString(_header, "alg");
    }
  }

  /// @return the parsed token, or `null` when it is not a compact JWT with JSON header and claims
  @Nullable
  public static Parsed parse(String token) {
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty()) {
      return null;
    }
    try {
      Base64.Decoder decoder = Base64.getUrlDecoder();
      Map<String, Object> header = Json.parseObject(new String(decoder.decode(parts[0]), StandardCharsets.UTF_8));
      Map<String, Object> claims = Json.parseObject(new String(decoder.decode(parts[1]), StandardCharsets.UTF_8));
      byte[] signature = decoder.decode(parts[2]);
      return new Parsed(header, claims, parts[0] + "." + parts[1], signature);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /// The JCA MAC name for a JWS HMAC algorithm.
  ///
  /// @throws IllegalArgumentException for any other algorithm (including `none`)
  public static String macName(String jwsAlgorithm) {
    switch (jwsAlgorithm) {
      case "HS256":
        return "HmacSHA256";
      case "HS384":
        return "HmacSHA384";
      case "HS512":
        return "HmacSHA512";
      default:
        throw new IllegalArgumentException("Not an HMAC algorithm: " + jwsAlgorithm);
    }
  }

  /// Checks the signature in constant time with the given secret, using the algorithm from the token header, which
  /// the caller must already have checked against its allow-list.
  public static boolean verifyHmac(Parsed jwt, byte[] secret) {
    String algorithm = jwt.getAlgorithm();
    if (algorithm == null) {
      return false;
    }
    return MessageDigest.isEqual(sign(macName(algorithm), secret, jwt._signingInput), jwt._signature);
  }

  /// Signs `header.claims` with HMAC; used by tests and by the mock identity provider.
  public static byte[] sign(String macName, byte[] secret, String signingInput) {
    try {
      Mac mac = Mac.getInstance(macName);
      mac.init(new SecretKeySpec(secret, macName));
      return mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Cannot compute " + macName, e);
    }
  }
}
