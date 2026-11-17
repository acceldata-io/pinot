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

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.cert.ManageCertificates;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nullable;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;


/// An embedded directory for the LDAP method's tests: an in-memory server with plain LDAP (StartTLS-capable), LDAPS
/// and a second LDAPS listener whose certificate names another host, plus a trust store an operator would build. It
/// imitates two Active Directory behaviours: a user principal name (`alice@example.com`) is accepted as bind name, and
/// the in-chain matching rule (`member:1.2.840.113556.1.4.1941:=<dn>`) is answered with the groups reached through
/// nested membership. Schema checking is off, so entries may carry `memberOf` and `sAMAccountName`.
final class EmbeddedLdap implements AutoCloseable {
  static final String BASE = "dc=example,dc=com";
  static final String IN_CHAIN = "1.2.840.113556.1.4.1941";
  static final String BIND_PASSWORD = "bind-test-password";
  private static final String TRUSTSTORE_PASSWORD = "truststore-test-password";
  private static final char[] KEYSTORE_PASSWORD = "server-keystore-test-password".toCharArray();

  static final SecretResolver SECRETS = alias -> {
    switch (alias) {
      case "ldap.bind.password":
        return BIND_PASSWORD.toCharArray();
      case "ldap.truststore.password":
        return TRUSTSTORE_PASSWORD.toCharArray();
      default:
        throw new IllegalArgumentException("unknown alias " + alias);
    }
  };

  final InMemoryDirectoryServer _server;
  final File _truststore;
  final int _ldapPort;
  final int _ldapsPort;
  final int _otherHostPort;
  final AtomicInteger _binds = new AtomicInteger();
  final List<String> _searchFilters = new CopyOnWriteArrayList<>();

  EmbeddedLdap(String... ldif)
      throws Exception {
    File serverKeyStore = selfSignedCertificate("localhost", "127.0.0.1");
    File otherHostKeyStore = selfSignedCertificate("other.invalid", null);
    SSLUtil serverSsl = new SSLUtil(new KeyStoreKeyManager(serverKeyStore, KEYSTORE_PASSWORD, "PKCS12", null),
        new TrustAllTrustManager());
    SSLUtil otherHostSsl = new SSLUtil(new KeyStoreKeyManager(otherHostKeyStore, KEYSTORE_PASSWORD, "PKCS12", null),
        new TrustAllTrustManager());
    InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE);
    config.setSchema(null);
    InetAddress loopback = InetAddress.getByName("localhost");
    config.setListenerConfigs(
        InMemoryListenerConfig.createLDAPConfig("ldap", loopback, 0, serverSsl.createSSLSocketFactory()),
        InMemoryListenerConfig.createLDAPSConfig("ldaps", loopback, 0, serverSsl.createSSLServerSocketFactory(), null),
        InMemoryListenerConfig.createLDAPSConfig("ldaps-other-host", loopback, 0,
            otherHostSsl.createSSLServerSocketFactory(), null));
    config.addInMemoryOperationInterceptor(new InMemoryOperationInterceptor() {
      @Override
      public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) {
        _binds.incrementAndGet();
        SimpleBindRequest bind = request.getRequest();
        String name = bind.getBindDN();
        if (name.endsWith("@example.com")) {
          request.setRequest(new SimpleBindRequest("uid=" + name.substring(0, name.indexOf('@')) + ",ou=people," + BASE,
              bind.getPassword().getValue()));
        }
      }

      @Override
      public void processSearchRequest(InMemoryInterceptedSearchRequest request)
          throws LDAPException {
        ReadOnlySearchRequest search = request.getRequest();
        String filter = search.getFilter().toString();
        _searchFilters.add(filter);
        Filter inChain = findInChain(search.getFilter());
        if (inChain != null) {
          // Active Directory's in-chain rule: every group the DN reaches through nested membership
          List<Filter> groups = new ArrayList<>();
          for (String group : nestedGroups(inChain.getAssertionValue(), new ArrayList<>())) {
            groups.add(Filter.createEqualityFilter("entryDN", group));
          }
          SearchRequest rewritten = search.duplicate();
          rewritten.setFilter(groups.isEmpty() ? Filter.createEqualityFilter("cn", "\u0000none")
              : Filter.createORFilter(groups));
          request.setRequest(rewritten);
        }
      }
    });
    _server = new InMemoryDirectoryServer(config);
    _server.add("dn: " + BASE, "objectClass: domain", "dc: example");
    for (String ou : new String[]{"people", "groups", "services"}) {
      _server.add("dn: ou=" + ou + "," + BASE, "objectClass: organizationalUnit", "ou: " + ou);
    }
    _server.add("dn: cn=pinot-bind,ou=services," + BASE, "objectClass: person", "cn: pinot-bind", "sn: bind",
        "userPassword: " + BIND_PASSWORD);
    if (ldif.length > 0) {
      _server.importFromLDIF(false, ldifFile(ldif));
    }
    _server.startListening();
    _ldapPort = _server.getListenPort("ldap");
    _ldapsPort = _server.getListenPort("ldaps");
    _otherHostPort = _server.getListenPort("ldaps-other-host");

    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    trust.setCertificateEntry("ldap", certificate(serverKeyStore));
    trust.setCertificateEntry("other-host", certificate(otherHostKeyStore));
    _truststore = File.createTempFile("ldap-trust", ".p12");
    _truststore.deleteOnExit();
    try (OutputStream out = new FileOutputStream(_truststore)) {
      trust.store(out, TRUSTSTORE_PASSWORD.toCharArray());
    }
  }

  @Nullable
  private static Filter findInChain(Filter filter) {
    if (filter.getFilterType() == Filter.FILTER_TYPE_EXTENSIBLE_MATCH && IN_CHAIN.equals(filter.getMatchingRuleID())) {
      return filter;
    }
    for (Filter component : filter.getComponents()) {
      Filter found = findInChain(component);
      if (found != null) {
        return found;
      }
    }
    return null;
  }

  /// Groups with `member: <dn>`, then their groups, and so on.
  private List<String> nestedGroups(String dn, List<String> seen)
      throws LDAPException {
    for (com.unboundid.ldap.sdk.SearchResultEntry group : _server.search("ou=groups," + BASE,
        com.unboundid.ldap.sdk.SearchScope.SUB, Filter.createEqualityFilter("member", dn)).getSearchEntries()) {
      if (!seen.contains(group.getDN())) {
        seen.add(group.getDN());
        nestedGroups(group.getDN(), seen);
      }
    }
    return seen;
  }

  private static String ldifFile(String... lines)
      throws Exception {
    File file = File.createTempFile("ldap-entries", ".ldif");
    file.deleteOnExit();
    try (OutputStream out = new FileOutputStream(file)) {
      out.write(String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
      out.write('\n');
    }
    return file.getAbsolutePath();
  }

  /// Search-then-bind over LDAPS with the trust store and the bind account.
  Map<String, Object> ldaps() {
    Map<String, Object> config = new HashMap<>();
    config.put("urls", "ldaps://localhost:" + _ldapsPort);
    config.put("truststore.path", _truststore.getAbsolutePath());
    config.put("truststore.password.alias", "ldap.truststore.password");
    config.put("bind.dn", "cn=pinot-bind,ou=services," + BASE);
    config.put("bind.password.alias", "ldap.bind.password");
    config.put("user.search.base", "ou=people," + BASE);
    return config;
  }

  static LdapAuthenticator authenticator(Map<String, Object> config) {
    LdapAuthenticator authenticator = new LdapAuthenticator();
    authenticator.init(new PinotConfiguration(config), SECRETS);
    return authenticator;
  }

  static AuthCredential basic(String user, String password) {
    return AuthCredential.parse("Basic " + Base64.getEncoder().encodeToString(
        (user + ":" + password).getBytes(StandardCharsets.UTF_8)));
  }

  /// A PKCS12 key store with a self-signed EC certificate for the host name (and IP address, if given).
  private static File selfSignedCertificate(String host, @Nullable String ip)
      throws Exception {
    File keyStore = File.createTempFile("ldap-server", ".p12");
    keyStore.delete();
    keyStore.deleteOnExit();
    List<String> args = new ArrayList<>(List.of("generate-self-signed-certificate", "--keystore",
        keyStore.getAbsolutePath(), "--keystore-password", new String(KEYSTORE_PASSWORD), "--keystore-type", "PKCS12",
        "--alias", "server", "--subject-dn", "CN=" + host, "--key-algorithm", "EC", "--key-size-bits", "256",
        "--signature-algorithm", "SHA256withECDSA", "--subject-alternative-name-dns", host));
    if (ip != null) {
      args.addAll(List.of("--subject-alternative-name-ip-address", ip));
    }
    OutputStream quiet = OutputStream.nullOutputStream();
    ResultCode result = ManageCertificates.main(null, quiet, quiet, args.toArray(new String[0]));
    if (result != ResultCode.SUCCESS) {
      throw new IllegalStateException("cannot create a test certificate: " + result);
    }
    return keyStore;
  }

  private static Certificate certificate(File keyStore)
      throws Exception {
    KeyStore source = KeyStore.getInstance("PKCS12");
    try (InputStream in = new FileInputStream(keyStore)) {
      source.load(in, KEYSTORE_PASSWORD);
    }
    return source.getCertificate(source.aliases().nextElement());
  }

  @Override
  public void close() {
    _server.shutDown(true);
  }
}
