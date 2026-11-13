<!--

    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.

-->
# Pinot OAuth 2.0 sample handlers

Starting points for connecting Pinot's `oauth2` authentication method to an identity provider that the built-in
handlers cannot express. Copy the module, adapt the code to your provider, build a jar and deploy it as a `java`
handler. Pinot supports the authentication SPI (`org.apache.pinot.plugin.auth.spi`) and the built-in handlers; the
samples are yours to change.

| File | What it is |
|---|---|
| `CustomIdpTokenHandler` | Validates tokens of an in-house provider: HMAC-signed JWT (shared secret), optional validation call, user / groups lookup, JSON mapping, error handling. Heavily commented. |
| `CustomIdpTokenSource` | Gets tokens for Pinot's own calls between roles from a non-standard token endpoint (form or JSON request). |
| `GoogleTokenHandler` | Google access tokens (`ya29.…`, opaque) through Google's token-info endpoint; the pattern for any provider with opaque tokens and a token-info call. |
| `support/Json`, `support/JsonMapping` | A small JSON reader and dotted-path mapping, so the samples need only the JDK. |
| `support/HttpCalls`, `support/Jwts` | Provider calls with timeouts and size cap; HMAC JWT parsing and verification. |
| `src/test/…` | Tests against a mock identity provider (valid, invalid, expired, revoked, provider down, slow), and a test that loads the packed jar through the `java` handler type. |
| `examples/*.properties` | Configuration for the java variant, the http-only variant and several providers side by side. |

## 1. Pick the handler

Go down the list and stop at the first that fits. Each step down means more code you own.

1. **`jwt`** (built in) – the provider issues JWTs signed with keys published as JWKS (RS / PS / ES), or with a shared
   secret, and the token itself carries the user (and ideally groups). Configuration only.
2. **`google`** (built in) – Google ID tokens for your OAuth client.
3. **`http`** (built in, preview) – the provider has an API that confirms a token and returns the user; nothing has to
   be checked inside Pinot. Configuration only: request template plus JSON mapping
   (`examples/custom-idp-http-only.properties`).
4. **`java`** with these samples – everything else, for example: the token is an HMAC JWT **without a user name**,
   so Pinot must verify the signature locally *and* look the user up; the provider signals errors in a non-standard
   way; several calls are needed; or groups come from a separate directory.

A token shaped like this is the case `CustomIdpTokenHandler` is written for:

```
header  {"typ":"JWT","alg":"HS512"}
claims  {"iss":"identityManager","version":"4.0","tid":"<tenant id>","sid":"<session id>","iat":…,"exp":…}
```

No `aud`, no `sub` / user name: the handler verifies the signature with the shared secret, checks `exp` / `iat` and
the required claims, optionally asks the provider whether the session is still live, and gets the user and groups
from the provider's user-info API.

## 2. Adapt the sample

The places you are most likely to change are marked in `CustomIdpTokenHandler`:

- **Recognise** (`validate`, step 1): which tokens are yours. Returning `null` passes the token to the next handler;
  throwing ends the request with 401. Keep the issuer check: the router uses `issuer` to route JWTs.
- **Provider answers** (`readAnswer`): by default 2xx = valid, 400 / 401 / 403 = invalid token, anything else =
  provider unavailable. If your provider returns 200 with an error field, check it here.
- **User lookup** (step 4): by default the user-info call sends the token as a bearer token. If your provider looks
  users up by a claim (for example the session id), build that request here.
- **Mapping** (step 5): `user.field`, `groups.field`, `scopes.field` take dotted paths, so most layouts need only
  configuration.

Rules that keep a custom handler safe – the tests check them, keep them when you change the code:

- Never accept a token on its unverified content: verify a signature, or have the provider confirm it, or both.
- Any failure (exception, timeout, unexpected answer) must reject the request, never let it through. The router adds
  a guard (timeout, exception → 401), but do not rely on it alone.
- Never put the token, the secret or a provider response body into an exception message or a log line.
- Read secrets only through `HandlerContext.getSecretResolver()`; never from configuration values.
- Use only the JDK, the SPI, `org.apache.pinot.spi.env` and SLF4J from Pinot. Anything else (Jackson, an HTTP
  library) must be in your jar or next to it in the handler directory: the handler class loader does not expose
  Pinot's own libraries.
- Keep `validate` fast: results are cached per token (`cache.ttl.seconds`, default 60 for `java` handlers), but the
  first call for a token is on the request path.

## 3. Build

In the Pinot source tree:

```
./mvnw -pl pinot-plugins/pinot-auth/pinot-auth-samples -am package
```

On its own (JDK 17, Maven, a repository with the Pinot artifacts of your version), from the source archive
`pinot-auth-samples-<version>-src.zip` that the build produces next to the jar:

```
unzip pinot-auth-samples-<version>-src.zip && cd pinot-auth-samples
mvn -Dpinot.version=<the Pinot version of your cluster> package
```

The tests run without network access (the identity provider is mocked). Build against the same Pinot version as the
cluster: the SPI is stable within a Pinot line, not across lines.

## 4. Deploy

On **every** Pinot host (controller, broker, server, minion):

1. Copy the jar (and any library it needs) to `<plugins dir>/pinot-auth-handlers/<handler name>/`, owned by the Pinot
   user, mode 0644. Only jars in that directory are loaded for that handler.
2. Store the secrets in Pinot's credential store under the aliases you configure (`hmac.secret.alias`,
   `client.secret.alias`) with the cluster management tooling. Configuration holds aliases, never secrets.
3. Add the handler settings (`examples/custom-idp-java-handler.properties`) to the configuration of every role.
4. Restart the roles. At start each role logs
   `Custom token handler <name> ready: issuer=…, local signature check=…, validation call=…`.

Check with a real token:

```
curl -i -H "Authorization: Bearer $TOKEN" https://<controller>:9443/tables
curl -i -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"sql":"select 1"}' https://<broker>:8099/query/sql
```

A rejected token answers `401` with `WWW-Authenticate: Bearer realm="pinot", error="invalid_token"`; the reason is in
the role's log, not in the response.

## 5. Cut-over

A cluster uses one authentication method (`pinot.auth.method`) on all roles; mixing methods between roles is refused
at start. Moving from Basic authentication to `oauth2`:

1. **Before the window.** Confirm that every client can get tokens from the provider; that every Pinot host reaches
   the provider endpoints (validation, user-info, token endpoint) through firewalls and proxies; that the token source
   for Pinot's own calls works (`CustomIdpTokenSource` or the built-in client-credentials source); and that the
   authorization rules name the users and groups the handler returns.
2. **Stage.** Deploy the jar and secrets to all hosts (deploying them does nothing until the method changes). Prepare
   the new configuration and keep the current one for rollback.
3. **Switch.** In a maintenance window: stop all roles, set `pinot.auth.method=oauth2` with the handler settings on all
   roles, start controllers, then servers and minions, then brokers.
4. **Verify.** A token query through the broker, a table listing on the controller, segment upload and a minion task;
   no `Identity provider unavailable` or `Invalid token` lines for Pinot's own service identity.
5. **Rollback.** Restore the previous configuration on all roles and restart them. Nothing is migrated, so rollback
   is a configuration change only.

## 6. Runbook

| Symptom | Log line (role log) | Likely cause | Action |
|---|---|---|---|
| Role does not start | `No handler jars in …` | Jar missing on this host | Copy the jar to `<plugins dir>/pinot-auth-handlers/<name>/` |
| Role does not start | `… is not available to token handlers; bundle it in the handler jar` | Handler uses a library Pinot does not expose | Add the library jar next to the handler jar |
| Role does not start | `Unknown alias …` / `a configured secret is empty` | Secret not in the credential store on this host | Store the secret under the configured alias |
| Role does not start | `set hmac.secret.alias, validation.url or both` | Handler would trust unverified tokens | Configure verification |
| All requests 401 | `Invalid token (<name>): bad signature` | Shared secret differs from the provider's (rotated?) | Update the secret on all hosts, restart |
| All requests 401 | `Identity provider unavailable for <name>: validation call failed` | Provider unreachable, DNS, proxy, TLS trust | Check reachability from the Pinot host; add the provider CA to the JVM truststore |
| Some requests 401 | `… rejected by the identity provider (… answered 401)` | Session revoked or expired at the provider | Expected; the client gets a new token |
| Some requests 401 | `Invalid token (<name>): expired` | Token past `exp` + `clock.skew.seconds` | Check client token refresh; check host clocks (NTP) |
| Requests 401 for tokens of another provider | `Token issuer is not configured` | No handler claims that issuer | Add a handler or fix `issuer` |
| Requests 401 under load | `Identity provider timeout (<name>)` | Provider slower than the handler `timeout.ms` | Check provider latency; adjust `http.timeout.ms` / `timeout.ms` |
| Requests 401, handler bug | `Token handler error (<name>)` | Handler threw an unexpected exception | Stack trace is in the log above the line; fix the handler |
| Slow first requests | — | Provider calls on the request path | Check provider latency; raise `cache.ttl.seconds` within your revocation tolerance |
| 403 after successful login | authorization log | User / groups not in the rules | Compare the mapped user and groups (audit log) with the rules |

Rotating the shared secret: store the new secret under a new alias on all hosts, set `hmac.secret.alias` to it and
`hmac.previous.secret.alias` to the old one, restart the roles one at a time, then let the provider switch to the new
secret. Once tokens signed with the old secret have expired, remove `hmac.previous.secret.alias` and restart again.
