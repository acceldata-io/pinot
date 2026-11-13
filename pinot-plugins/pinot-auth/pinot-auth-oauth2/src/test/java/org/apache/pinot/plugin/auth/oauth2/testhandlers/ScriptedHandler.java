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
package org.apache.pinot.plugin.auth.oauth2.testhandlers;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.HandlerContext;
import org.apache.pinot.plugin.auth.spi.OAuthTokenHandler;
import org.apache.pinot.plugin.auth.spi.TokenIdentity;


/// Custom handler used by the tests, packed into a jar at test time. Behaviour by `mode`:
/// - `accept`: opaque tokens `ok-<user>` are accepted, `bad-*` rejected, anything else not recognised (null);
/// - `jwt-tid`: reads the JWT payload (no signature check: test only) and returns the `tid` claim as user;
/// - `throw` / `error` / `slow` / `null`: fails with a RuntimeException / an Error / sleeps 3 s / returns null;
/// - every identity carries the handler's class loader and whether it can see a non-SPI Pinot class.
public class ScriptedHandler implements OAuthTokenHandler {
  public static final AtomicInteger CALLS = new AtomicInteger();
  private String _mode;
  private String _setting;

  @Override
  public void init(HandlerContext context) {
    _mode = context.getConfig().getProperty("mode", "accept");
    _setting = context.getConfig().getProperty("custom.setting", "");
  }

  @Override
  public TokenIdentity validate(String token) {
    CALLS.incrementAndGet();
    switch (_mode) {
      case "throw":
        throw new IllegalStateException("handler bug");
      case "error":
        throw new NoClassDefFoundError("missing/Dependency");
      case "slow":
        try {
          Thread.sleep(3000);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
        return identity("slow");
      case "null":
        return null;
      case "jwt-tid": {
        String payload = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8);
        int start = payload.indexOf("\"tid\":\"") + 7;
        return identity(payload.substring(start, payload.indexOf('"', start)));
      }
      default:
        if (token.startsWith("ok-")) {
          return identity(token.substring(3));
        }
        if (token.startsWith("bad-")) {
          throw new AuthenticationException("rejected by custom provider",
              AuthenticationException.challengeFor(AuthMethod.OAUTH2));
        }
        return null;
    }
  }

  private TokenIdentity identity(String user) {
    Map<String, Object> attributes = new HashMap<>();
    attributes.put("loader", getClass().getClassLoader().getClass().getName());
    attributes.put("setting", _setting);
    boolean seesPinotInternals;
    try {
      Class.forName("org.apache.pinot.spi.utils.CommonConstants", false, getClass().getClassLoader());
      seesPinotInternals = true;
    } catch (ClassNotFoundException e) {
      seesPinotInternals = false;
    }
    attributes.put("seesPinotInternals", seesPinotInternals);
    attributes.put("contextLoaderIsOwn", Thread.currentThread().getContextClassLoader() == getClass().getClassLoader());
    return new TokenIdentity(user, Set.of("custom"), Set.of(), Instant.now().plusSeconds(300), null, attributes);
  }
}
