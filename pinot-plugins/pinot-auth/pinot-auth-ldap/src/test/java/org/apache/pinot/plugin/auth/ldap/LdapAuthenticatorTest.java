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
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.ResultCode;
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
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.pinot.plugin.auth.spi.AuthCredential;
import org.apache.pinot.plugin.auth.spi.AuthMethodSelector;
import org.apache.pinot.plugin.auth.spi.AuthenticationException;
import org.apache.pinot.plugin.auth.spi.PinotAuthenticator;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.SecretResolver;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// [LdapAuthenticator] against an embedded directory with plain LDAP, LDAPS and StartTLS listeners: both bind modes
/// (including an Active Directory principal name), transport rules, trust, failover and rejected credentials.
public class LdapAuthenticatorTest {
  static final String BASE = "dc=example,dc=com";
  private static final String TRUSTSTORE_PASSWORD = "truststore-test-password";
  private static final char[] KEYSTORE_PASSWORD = "server-keystore-test-password".toCharArray();
  private static final String BIND_PASSWORD = "bind-test-password";
  private static final String ALICE_PASSWORD = "alice-test-password";

  private InMemoryDirectoryServer _server;
  private File _truststore;
  private int _ldapPort;
  private int _ldapsPort;
  private int _otherHostPort;
  private final AtomicInteger _binds = new AtomicInteger();

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

  @BeforeClass
  public void startServer()
      throws Exception {
    // Server certificate for localhost, as a directory's certificate names its host, and one issued for another host
    File serverKeyStore = selfSignedCertificate("localhost", "127.0.0.1");
    File otherHostKeyStore = selfSignedCertificate("other.invalid", null);
    SSLUtil serverSsl = new SSLUtil(new KeyStoreKeyManager(serverKeyStore, KEYSTORE_PASSWORD, "PKCS12", null),
        new TrustAllTrustManager());
    SSLUtil otherHostSsl = new SSLUtil(new KeyStoreKeyManager(otherHostKeyStore, KEYSTORE_PASSWORD, "PKCS12", null),
        new TrustAllTrustManager());
    InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE);
    InetAddress loopback = InetAddress.getByName("localhost");
    config.setListenerConfigs(
        InMemoryListenerConfig.createLDAPConfig("ldap", loopback, 0, serverSsl.createSSLSocketFactory()),
        InMemoryListenerConfig.createLDAPSConfig("ldaps", loopback, 0, serverSsl.createSSLServerSocketFactory(), null),
        InMemoryListenerConfig.createLDAPSConfig("ldaps-other-host", loopback, 0,
            otherHostSsl.createSSLServerSocketFactory(), null));
    // Active Directory accepts a user principal name (alice@example.com) as bind name: map it to the entry's DN
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
    });
    _server = new InMemoryDirectoryServer(config);
    _server.add("dn: " + BASE, "objectClass: domain", "dc: example");
    _server.add("dn: ou=people," + BASE, "objectClass: organizationalUnit", "ou: people");
    _server.add("dn: ou=services," + BASE, "objectClass: organizationalUnit", "ou: services");
    _server.add("dn: cn=pinot-bind,ou=services," + BASE, "objectClass: person", "cn: pinot-bind", "sn: bind",
        "userPassword: " + BIND_PASSWORD);
    _server.add("dn: uid=alice,ou=people," + BASE, "objectClass: inetOrgPerson", "uid: alice", "cn: Alice",
        "sn: A", "userPassword: " + ALICE_PASSWORD);
    _server.add("dn: uid=o\\,brien,ou=people," + BASE, "objectClass: inetOrgPerson", "uid: o,brien", "cn: OBrien",
        "sn: O", "userPassword: obrien-test-password");
    _server.add("dn: uid=alice2,ou=people," + BASE, "objectClass: inetOrgPerson", "uid: alice2", "cn: Alice",
        "sn: A", "userPassword: other-test-password");
    _server.startListening();
    _ldapPort = _server.getListenPort("ldap");
    _ldapsPort = _server.getListenPort("ldaps");
    _otherHostPort = _server.getListenPort("ldaps-other-host");

    // Trust store with the servers' certificates, as an operator would build it
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

  /// A PKCS12 key store with a self-signed EC certificate for the host name (and IP address, if given).
  private static File selfSignedCertificate(String host, String ip)
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
    assertEquals(ManageCertificates.main(null, quiet, quiet, args.toArray(new String[0])), ResultCode.SUCCESS);
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

  @AfterClass
  public void stopServer() {
    _server.shutDown(true);
  }

  @BeforeMethod
  public void resetCounters() {
    _binds.set(0);
  }

  int ldapPort() {
    return _ldapPort;
  }

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

  static void assertRefused(PinotAuthenticator authenticator, AuthCredential credential, String message) {
    AuthenticationException e =
        expectThrows(AuthenticationException.class, () -> authenticator.authenticate(credential));
    assertTrue(e.getMessage().startsWith(message), e.getMessage());
    assertEquals(e.getChallenge(), "Basic realm=\"pinot\"");
  }

  @Test
  public void testSearchThenBindOverLdaps() {
    LdapAuthenticator authenticator = authenticator(ldaps());
    PinotPrincipal principal = authenticator.authenticate(basic("alice", ALICE_PASSWORD));
    assertEquals(principal.getUser(), "alice");
    assertEquals(principal.getClaims().get("dn"), "uid=alice,ou=people," + BASE);
    assertFalse(principal.isServiceAccount());
    assertRefused(authenticator, basic("alice", "wrong"), "Invalid user name or password");
    assertRefused(authenticator, basic("nobody", "x"), "Invalid user name or password");
    // A user name with a DN special character is found by search
    assertEquals(authenticator.authenticate(basic("o,brien", "obrien-test-password")).getUser(), "o,brien");
  }

  @Test
  public void testEmptyPasswordIsRefusedWithoutABind() {
    LdapAuthenticator authenticator = authenticator(ldaps());
    _binds.set(0);
    assertRefused(authenticator, basic("alice", ""), "Invalid user name or password");
    // An empty password would be an unauthenticated bind, which directories accept: none is sent
    assertEquals(_binds.get(), 0);
  }

  @Test
  public void testFilterInjectionDoesNotMatchOtherEntries() {
    LdapAuthenticator authenticator = authenticator(ldaps());
    // Wildcards and filter syntax are escaped: none of these names finds alice (or any entry)
    for (String name : new String[]{"*", "al*", "alice)(uid=*", "*)(|(uid=*", "alice\\", "\u0000"}) {
      assertRefused(authenticator, basic(name, ALICE_PASSWORD), "Invalid user name or password");
    }
  }

  @Test
  public void testDirectBindWithDnPatternOverStartTls() {
    Map<String, Object> config = new HashMap<>();
    config.put("urls", "ldap://localhost:" + _ldapPort);
    config.put("start.tls", "true");
    config.put("truststore.path", _truststore.getAbsolutePath());
    config.put("truststore.password.alias", "ldap.truststore.password");
    config.put("bind.mode", "direct");
    config.put("user.dn.pattern", "uid={0},ou=people," + BASE);
    LdapAuthenticator authenticator = authenticator(config);
    PinotPrincipal principal = authenticator.authenticate(basic("alice", ALICE_PASSWORD));
    assertEquals(principal.getClaims().get("dn"), "uid=alice,ou=people," + BASE);
    // The name is escaped as a DN value
    assertEquals(authenticator.authenticate(basic("o,brien", "obrien-test-password")).getUser(), "o,brien");
    assertRefused(authenticator, basic("alice", "wrong"), "Invalid user name or password");
    assertRefused(authenticator, basic("alice,ou=services", ALICE_PASSWORD), "Invalid user name or password");
  }

  @Test
  public void testDirectBindWithActiveDirectoryPrincipalName() {
    Map<String, Object> config = ldaps();
    config.remove("bind.dn");
    config.remove("bind.password.alias");
    config.put("bind.mode", "direct");
    config.put("user.dn.pattern", "{0}@example.com");
    config.put("user.search.filter", "(uid={0})");
    LdapAuthenticator authenticator = authenticator(config);
    assertEquals(authenticator.authenticate(basic("alice", ALICE_PASSWORD)).getClaims().get("dn"),
        "uid=alice,ou=people," + BASE);
    assertRefused(authenticator, basic("alice", "wrong"), "Invalid user name or password");
    // A principal-name pattern needs a search base to read the entry
    config.remove("user.search.base");
    expectThrows(IllegalArgumentException.class, () -> authenticator(config));
  }

  @Test
  public void testTransportRules() {
    Map<String, Object> plain = ldaps();
    plain.put("urls", "ldap://localhost:" + _ldapPort);
    plain.remove("truststore.path");
    // Passwords in clear text only when explicitly allowed (tests)
    IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> authenticator(plain));
    assertTrue(e.getMessage().contains("clear text"), e.getMessage());
    plain.put("allow.insecure", "true");
    assertEquals(authenticator(plain).authenticate(basic("alice", ALICE_PASSWORD)).getUser(), "alice");
    // The server certificate must be trusted: without the trust store the connection is refused, never accepted
    Map<String, Object> untrusted = ldaps();
    untrusted.remove("truststore.path");
    untrusted.remove("truststore.password.alias");
    assertRefused(authenticator(untrusted), basic("alice", ALICE_PASSWORD), "Directory unavailable");
    // Host name verification: a trusted certificate issued for another host is refused
    Map<String, Object> otherHost = ldaps();
    otherHost.put("urls", "ldaps://localhost:" + _otherHostPort);
    assertRefused(authenticator(otherHost), basic("alice", ALICE_PASSWORD), "Directory unavailable");
    Map<String, Object> mixed = ldaps();
    mixed.put("start.tls", "true");
    expectThrows(IllegalArgumentException.class, () -> authenticator(mixed));
    Map<String, Object> mixedSchemes = ldaps();
    mixedSchemes.put("allow.insecure", "true");
    mixedSchemes.put("urls", "ldaps://localhost:" + _ldapsPort + ",ldap://localhost:" + _ldapPort);
    expectThrows(IllegalArgumentException.class, () -> authenticator(mixedSchemes));
  }

  @Test
  public void testFailoverAndOutage()
      throws Exception {
    int closed;
    try (ServerSocket socket = new ServerSocket(0)) {
      closed = socket.getLocalPort();
    }
    Map<String, Object> config = ldaps();
    config.put("connect.timeout.ms", "1000");
    config.put("urls", "ldaps://localhost:" + closed + ",ldaps://localhost:" + _ldapsPort);
    assertEquals(authenticator(config).authenticate(basic("alice", ALICE_PASSWORD)).getUser(), "alice");
    config.put("urls", "ldaps://localhost:" + closed);
    assertRefused(authenticator(config), basic("alice", ALICE_PASSWORD), "Directory unavailable");
  }

  @Test
  public void testServiceUsersAndMalformedCredentials() {
    Map<String, Object> config = ldaps();
    config.put("service.users", "alice");
    LdapAuthenticator authenticator = authenticator(config);
    assertTrue(authenticator.authenticate(basic("alice", ALICE_PASSWORD)).isServiceAccount());
    assertRefused(authenticator, AuthCredential.parse("Basic !!!"), "Invalid user name or password");
    assertRefused(authenticator, AuthCredential.parse("Basic " + Base64.getEncoder().encodeToString(
        "no-colon".getBytes(StandardCharsets.UTF_8))), "Invalid user name or password");
    // Padding removed by a client is accepted
    String unpadded = Base64.getEncoder().withoutPadding().encodeToString(
        ("alice:" + ALICE_PASSWORD).getBytes(StandardCharsets.UTF_8));
    assertEquals(authenticator.authenticate(AuthCredential.parse("Basic " + unpadded)).getUser(), "alice");
  }

  @Test
  public void testSelectedThroughTheSpi() {
    Map<String, Object> config = new HashMap<>();
    config.put("pinot.auth.method", "ldap");
    ldaps().forEach((k, v) -> config.put("pinot.auth.ldap." + k, v));
    PinotAuthenticator authenticator = AuthMethodSelector.create(new PinotConfiguration(config), SECRETS);
    assertTrue(authenticator instanceof LdapAuthenticator);
    assertEquals(authenticator.authenticate(basic("alice", ALICE_PASSWORD)).getUser(), "alice");
  }

  @Test
  public void testConfigurationErrors() {
    Map<String, Object> noUrls = ldaps();
    noUrls.remove("urls");
    expectThrows(IllegalArgumentException.class, () -> authenticator(noUrls));
    Map<String, Object> noBind = ldaps();
    noBind.remove("bind.dn");
    expectThrows(IllegalArgumentException.class, () -> authenticator(noBind));
    Map<String, Object> badMode = ldaps();
    badMode.put("bind.mode", "anonymous");
    expectThrows(IllegalArgumentException.class, () -> authenticator(badMode));
    Map<String, Object> badFilter = ldaps();
    badFilter.put("user.search.filter", "(uid=alice)");
    expectThrows(IllegalArgumentException.class, () -> authenticator(badFilter));
    Map<String, Object> badAlias = ldaps();
    badAlias.put("bind.password.alias", "missing");
    expectThrows(IllegalArgumentException.class, () -> authenticator(badAlias));
  }
}
