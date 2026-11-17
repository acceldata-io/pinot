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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import javax.annotation.Nullable;
import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;


/// Connections to the directory of the `ldap` method, with the JDK's JNDI LDAP provider: transport security,
/// failover, timeouts and the two ways of checking a user's password.
///
/// - Transport: every URL must be `ldaps://`, or `ldap://` with `start.tls=true`; plain `ldap://` without StartTLS is
///   refused unless `allow.insecure=true` (tests only), because the user's password is sent in the bind. Server
///   certificates are checked against `truststore.path` (type `truststore.type`, default PKCS12, password from the
///   credential store alias `truststore.password.alias`) or the JVM's default trust store, and the host name must match
///   the certificate.
/// - Failover: `urls` is a comma-separated list; the servers are tried in order until one accepts the connection,
///   each within `connect.timeout.ms` (default 5000); answers must come within `read.timeout.ms` (default 10000). A
///   wrong password is never retried on another server.
/// - `bind.mode=search` (default): the bind account (`bind.dn`, password from the credential store alias
///   `bind.password.alias`) searches `user.search.base` (scope `user.search.scope` = `subtree` (default) or
///   `one`) with `user.search.filter` (default `(uid={0})`, `{0}` = the escaped login name); exactly one entry must
///   match, then the user binds as that entry with the password. Bind-account connections are pooled by JNDI: plain
///   `ldap://` by default, `ldaps://` when the JVM sets `com.sun.jndi.ldap.connect.pool.protocol=plain ssl`; StartTLS
///   connections are not pooled.
/// - `bind.mode=direct`: the user binds as `user.dn.pattern` with `{0}` = the login name, e.g.
///   `uid={0},ou=people,dc=example,dc=com` (the name is escaped as a DN value) or an Active Directory user principal
///   name `{0}@corp.example.com`; the entry is then read with the user's own connection, by search (`user.search.base`
///   + `user.search.filter`) when `user.search.base` is set (required for a principal-name pattern, which is not a DN),
///   else by the bound DN.
///
/// Thread-safe after construction.
final class LdapDirectory {
  static final String CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

  enum BindMode {
    SEARCH, DIRECT
  }

  /// The password was wrong, the user is unknown or ambiguous, or the account cannot sign in.
  static final class InvalidCredentialsException extends Exception {
    InvalidCredentialsException(String message) {
      super(message);
    }
  }

  /// No directory server could be reached or answered in time.
  static final class DirectoryUnavailableException extends Exception {
    DirectoryUnavailableException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /// A user found and authenticated in the directory.
  static final class Entry {
    final String _dn;
    final Attributes _attributes;

    Entry(String dn, Attributes attributes) {
      _dn = dn;
      _attributes = attributes;
    }
  }

  private final List<String> _urls;
  private final boolean _startTls;
  private final boolean _ldaps;
  private final BindMode _bindMode;
  @Nullable
  private final SSLSocketFactory _sslFactory;
  private final int _connectTimeoutMs;
  private final int _readTimeoutMs;
  @Nullable
  private final String _bindDn;
  @Nullable
  private final String _bindPasswordAlias;
  private final SecretResolver _secrets;
  @Nullable
  private final String _userSearchBase;
  private final String _userSearchFilter;
  private final int _userSearchScope;
  @Nullable
  private final String _userDnPattern;
  private final String[] _returnedAttributes;

  LdapDirectory(PinotConfiguration config, SecretResolver secrets, String[] returnedAttributes) {
    _secrets = secrets;
    _returnedAttributes = returnedAttributes;
    _urls = new ArrayList<>();
    for (String url : config.getProperty("urls", "").split(",")) {
      if (!url.trim().isEmpty()) {
        _urls.add(url.trim());
      }
    }
    if (_urls.isEmpty()) {
      throw new IllegalArgumentException("LDAP: urls must name at least one ldaps:// or ldap:// server");
    }
    _startTls = config.getProperty("start.tls", false);
    boolean allowInsecure = config.getProperty("allow.insecure", false);
    boolean anyLdaps = false;
    for (String url : _urls) {
      String scheme;
      try {
        scheme = URI.create(url).getScheme();
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("LDAP: malformed URL '" + url + "'");
      }
      if ("ldaps".equalsIgnoreCase(scheme)) {
        anyLdaps = true;
      } else if (!"ldap".equalsIgnoreCase(scheme)) {
        throw new IllegalArgumentException("LDAP: unsupported URL '" + url + "' (ldaps:// or ldap://)");
      } else if (!_startTls && !allowInsecure) {
        throw new IllegalArgumentException("LDAP: '" + url + "' would send passwords in clear text: use ldaps://, "
            + "start.tls=true, or allow.insecure=true for tests");
      }
    }
    if (anyLdaps && _startTls) {
      throw new IllegalArgumentException("LDAP: start.tls applies to ldap:// URLs only; do not mix it with ldaps://");
    }
    _ldaps = anyLdaps;
    for (String url : _urls) {
      // JNDI uses one socket setting for all URLs of a connection
      if (_ldaps != "ldaps".equalsIgnoreCase(URI.create(url).getScheme())) {
        throw new IllegalArgumentException("LDAP: urls mix ldaps:// and ldap://; use one scheme for all servers");
      }
    }
    _sslFactory = sslFactory(config, secrets);
    _connectTimeoutMs = config.getProperty("connect.timeout.ms", 5000);
    _readTimeoutMs = config.getProperty("read.timeout.ms", 10000);
    String mode = config.getProperty("bind.mode", "search").trim().toUpperCase(Locale.ROOT);
    try {
      _bindMode = BindMode.valueOf(mode);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("LDAP: bind.mode must be search or direct, not '" + mode + "'");
    }
    _userSearchBase = trimToNull(config.getProperty("user.search.base"));
    _userSearchFilter = config.getProperty("user.search.filter", "(uid={0})").trim();
    String scope = config.getProperty("user.search.scope", "subtree").trim().toLowerCase(Locale.ROOT);
    if (!scope.equals("subtree") && !scope.equals("one")) {
      throw new IllegalArgumentException("LDAP: user.search.scope must be subtree or one");
    }
    _userSearchScope = scope.equals("one") ? SearchControls.ONELEVEL_SCOPE : SearchControls.SUBTREE_SCOPE;
    _userDnPattern = trimToNull(config.getProperty("user.dn.pattern"));
    _bindDn = trimToNull(config.getProperty("bind.dn"));
    _bindPasswordAlias = trimToNull(config.getProperty("bind.password.alias"));
    if (_bindMode == BindMode.SEARCH) {
      if (_bindDn == null || _bindPasswordAlias == null || _userSearchBase == null) {
        throw new IllegalArgumentException("LDAP: bind.mode=search needs bind.dn, bind.password.alias and "
            + "user.search.base");
      }
      _secrets.resolve(_bindPasswordAlias);  // fail at start, not at the first sign-in
    } else if (_userDnPattern == null || !_userDnPattern.contains("{0}")) {
      throw new IllegalArgumentException("LDAP: bind.mode=direct needs user.dn.pattern with {0}");
    } else if (!_userDnPattern.contains("=") && _userSearchBase == null) {
      throw new IllegalArgumentException("LDAP: user.dn.pattern '" + _userDnPattern
          + "' is a principal name, not a DN: set user.search.base (and user.search.filter, e.g. "
          + "(sAMAccountName={0})) to read the user's entry");
    }
    if (!_userSearchFilter.contains("{0}")) {
      throw new IllegalArgumentException("LDAP: user.search.filter must contain {0}");
    }
  }

  BindMode getBindMode() {
    return _bindMode;
  }

  /// Checks the password and returns the user's entry.
  Entry authenticate(String login, char[] password)
      throws InvalidCredentialsException, DirectoryUnavailableException {
    if (password.length == 0) {
      // An empty password makes a "simple" bind unauthenticated, which servers accept: never send one
      throw new InvalidCredentialsException("empty password");
    }
    if (_bindMode == BindMode.SEARCH) {
      Entry entry;
      LdapContext service = open(_bindDn, secret(_bindPasswordAlias), true);
      try {
        entry = findUser(service, login);
      } finally {
        close(service);
      }
      close(open(entry._dn, password, false));
      return entry;
    }
    // In a DN the name is a value and is escaped as such; a principal name (user@domain) is passed as typed
    String bindName = LdapEscaping.format(_userDnPattern,
        _userDnPattern.contains("=") ? LdapEscaping.dnValue(login) : login, null);
    LdapContext user = open(bindName, password, false);
    try {
      if (_userSearchBase != null) {
        return findUser(user, login);
      }
      return new Entry(bindName, user.getAttributes(bindName, _returnedAttributes));
    } catch (NamingException e) {
      throw unavailable("reading the user's entry", e);
    } finally {
      close(user);
    }
  }

  /// Searches with an open context. Used for the user and, by the group lookup, for the user's groups.
  List<SearchResult> search(LdapContext context, String base, String filter, int scope, String[] attributes,
      long limit)
      throws NamingException {
    SearchControls controls = new SearchControls();
    controls.setSearchScope(scope);
    controls.setReturningAttributes(attributes);
    controls.setCountLimit(limit);
    controls.setTimeLimit(_readTimeoutMs);
    List<SearchResult> results = new ArrayList<>();
    NamingEnumeration<SearchResult> answer = context.search(base, filter, controls);
    try {
      while (answer.hasMore()) {
        results.add(answer.next());
      }
    } finally {
      answer.close();
    }
    return results;
  }

  private Entry findUser(LdapContext context, String login)
      throws InvalidCredentialsException, DirectoryUnavailableException {
    String filter = LdapEscaping.format(_userSearchFilter, LdapEscaping.filterValue(login), null);
    List<SearchResult> found;
    try {
      found = search(context, _userSearchBase, filter, _userSearchScope, _returnedAttributes, 2);
    } catch (javax.naming.SizeLimitExceededException e) {
      throw new InvalidCredentialsException("more than one entry matches the user name");
    } catch (NamingException e) {
      throw unavailable("searching the user", e);
    }
    if (found.isEmpty()) {
      throw new InvalidCredentialsException("no entry matches the user name");
    }
    if (found.size() > 1) {
      throw new InvalidCredentialsException("more than one entry matches the user name");
    }
    return new Entry(found.get(0).getNameInNamespace(), found.get(0).getAttributes());
  }

  /// Opens a context bound as the given name, on the first server that answers.
  LdapContext open(String name, char[] password, boolean pooled)
      throws InvalidCredentialsException, DirectoryUnavailableException {
    Hashtable<String, Object> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
    env.put(Context.PROVIDER_URL, String.join(" ", _urls));
    env.put("java.naming.ldap.version", "3");
    env.put(Context.REFERRAL, "ignore");
    env.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(_connectTimeoutMs));
    env.put("com.sun.jndi.ldap.read.timeout", Integer.toString(_readTimeoutMs));
    // The truststore's factory for LDAPS connections; StartTLS gets it when the TLS layer is negotiated
    boolean ldapsFactory = _ldaps && _sslFactory != null;
    if (ldapsFactory) {
      env.put("java.naming.ldap.factory.socket", LdapSocketFactory.class.getName());
    }
    if (pooled && !_startTls) {
      env.put("com.sun.jndi.ldap.connect.pool", "true");
    }
    if (!_startTls) {
      env.put(Context.SECURITY_AUTHENTICATION, "simple");
      env.put(Context.SECURITY_PRINCIPAL, name);
      env.put(Context.SECURITY_CREDENTIALS, password);
    } else {
      env.put(Context.SECURITY_AUTHENTICATION, "none");
    }
    if (ldapsFactory) {
      LdapSocketFactory.set(_sslFactory);
    }
    LdapContext context = null;
    try {
      context = new InitialLdapContext(env, null);
      if (_startTls) {
        StartTlsResponse tls = (StartTlsResponse) context.extendedOperation(new StartTlsRequest());
        try {
          if (_sslFactory != null) {
            tls.negotiate(_sslFactory);
          } else {
            tls.negotiate();
          }
        } catch (IOException e) {
          throw new CommunicationException("StartTLS failed: " + e.getMessage());
        }
        context.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
        context.addToEnvironment(Context.SECURITY_PRINCIPAL, name);
        context.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
        // Binds now, on this connection (inside TLS); a new connection would be opened without it
        context.reconnect(null);
      }
      return context;
    } catch (AuthenticationException e) {
      close(context);
      throw new InvalidCredentialsException("the directory refused the password");
    } catch (NamingException e) {
      close(context);
      throw unavailable("connecting to " + String.join(", ", _urls), e);
    } finally {
      LdapSocketFactory.clear();
    }
  }

  private char[] secret(String alias) {
    return _secrets.resolve(alias);
  }

  private static DirectoryUnavailableException unavailable(String what, NamingException e) {
    String reason = e instanceof CommunicationException || e instanceof ServiceUnavailableException
        ? "server unreachable" : e.getClass().getSimpleName();
    return new DirectoryUnavailableException("LDAP directory unavailable (" + what + ": " + reason + ")", e);
  }

  static void close(@Nullable LdapContext context) {
    if (context != null) {
      try {
        context.close();
      } catch (NamingException e) {
        // nothing to do
      }
    }
  }

  @Nullable
  private static SSLSocketFactory sslFactory(PinotConfiguration config, SecretResolver secrets) {
    String path = trimToNull(config.getProperty("truststore.path"));
    if (path == null) {
      return null;
    }
    String type = config.getProperty("truststore.type", "PKCS12").trim();
    String alias = trimToNull(config.getProperty("truststore.password.alias"));
    try (InputStream in = Files.newInputStream(Paths.get(path))) {
      KeyStore store = KeyStore.getInstance(type);
      store.load(in, alias != null ? secrets.resolve(alias) : null);
      TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trust.init(store);
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(null, trust.getTrustManagers(), null);
      return context.getSocketFactory();
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalArgumentException("LDAP: cannot load truststore.path '" + path + "': " + e.getMessage(), e);
    }
  }

  @Nullable
  static String trimToNull(@Nullable String value) {
    return value == null || value.trim().isEmpty() ? null : value.trim();
  }
}
