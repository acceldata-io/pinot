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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.AuthorizationMode;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotAuthorizer;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Test doubles for the authentication and authorization framework, usable by class name from configuration:
/// - [Authenticator]: OAuth 2.0 method; bearer token `<user>` or `<user>:<group>,<group>`; token `bad` is rejected.
/// - [Authorizer]: native mode; allows exactly the requests listed in [Authorizer#ALLOWED] (as `<user> <request>`),
///   records every request in [Authorizer#SEEN], throws for the user `boom`.
public final class TestAuth {
  private TestAuth() {
  }

  public static class Authenticator implements PinotAuthenticator {
    @Override
    public AuthMethod getMethod() {
      return AuthMethod.OAUTH2;
    }

    @Override
    public void init(PinotConfiguration config, SecretResolver secretResolver) {
    }

    @Override
    public PinotPrincipal authenticate(AuthCredential credential) {
      String token = credential.getValue();
      if (token.equals("bad")) {
        throw new AuthenticationException("Invalid token", "Bearer realm=\"pinot\", error=\"invalid_token\"");
      }
      int colon = token.indexOf(':');
      String user = colon < 0 ? token : token.substring(0, colon);
      List<String> groups = colon < 0 ? Collections.emptyList() : Arrays.asList(token.substring(colon + 1).split(","));
      return new PinotPrincipal(user, new LinkedHashSet<>(groups), AuthMethod.OAUTH2, false, Map.of());
    }
  }

  public static class Authorizer implements PinotAuthorizer {
    public static final List<String> ALLOWED = Collections.synchronizedList(new ArrayList<>());
    public static final List<String> SEEN = Collections.synchronizedList(new ArrayList<>());

    @Override
    public AuthorizationMode getMode() {
      return AuthorizationMode.NATIVE;
    }

    @Override
    public void init(PinotConfiguration config) {
    }

    @Override
    public AuthorizationDecision authorize(PinotPrincipal principal, AccessRequest request) {
      if (principal.getUser().equals("boom")) {
        throw new IllegalStateException("authorizer failure");
      }
      String key = principal.getUser() + " " + request;
      SEEN.add(key);
      return ALLOWED.contains(key) ? AuthorizationDecision.allow("listed") : AuthorizationDecision.deny("not listed");
    }
  }

  /// Settings selecting both doubles.
  public static Map<String, Object> settings() {
    return new HashMap<>(Map.of(
        "pinot.auth.method", "oauth2",
        "pinot.auth.oauth2.authenticator.class", Authenticator.class.getName(),
        "pinot.authz.native.authorizer.class", Authorizer.class.getName()));
  }
}
