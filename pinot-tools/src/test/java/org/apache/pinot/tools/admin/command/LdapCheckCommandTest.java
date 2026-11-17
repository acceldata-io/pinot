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
package org.apache.pinot.tools.admin.command;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;


/// [LdapCheckCommand] against an embedded directory with native rules: the resolved identity and decisions, a
/// rejected password, and nothing secret in the output.
public class LdapCheckCommandTest {
  private static final String BASE = "dc=example,dc=com";
  private static final String BIND_PASSWORD = "ldap-check-bind-test-password";
  private static final String ALICE_PASSWORD = "ldap-check-alice-test-password";

  private InMemoryDirectoryServer _server;
  private File _config;

  @BeforeClass
  public void setUp()
      throws Exception {
    InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE);
    config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("ldap", 0));
    _server = new InMemoryDirectoryServer(config);
    _server.add("dn: " + BASE, "objectClass: domain", "dc: example");
    _server.add("dn: ou=people," + BASE, "objectClass: organizationalUnit", "ou: people");
    _server.add("dn: ou=groups," + BASE, "objectClass: organizationalUnit", "ou: groups");
    _server.add("dn: cn=bind," + BASE, "objectClass: person", "cn: bind", "sn: b", "userPassword: " + BIND_PASSWORD);
    _server.add("dn: uid=alice,ou=people," + BASE, "objectClass: inetOrgPerson", "uid: alice", "cn: Alice", "sn: A",
        "userPassword: " + ALICE_PASSWORD);
    _server.add("dn: cn=analysts,ou=groups," + BASE, "objectClass: groupOfNames", "cn: analysts",
        "member: uid=alice,ou=people," + BASE);
    _server.startListening();
    _config = File.createTempFile("ldap-check", ".properties");
    _config.deleteOnExit();
    Files.writeString(_config.toPath(), String.join("\n",
        "pinot.auth.method=ldap",
        "pinot.auth.ldap.urls=ldap://localhost:" + _server.getListenPort(),
        "pinot.auth.ldap.allow.insecure=true",
        "pinot.auth.ldap.bind.dn=cn=bind," + BASE,
        "pinot.auth.ldap.bind.password.alias=ldap.bind.password",
        "pinot.auth.secrets.ldap.bind.password=" + BIND_PASSWORD,
        "pinot.auth.ldap.user.search.base=ou=people," + BASE,
        "pinot.auth.ldap.group.mode=search",
        "pinot.auth.ldap.group.search.base=ou=groups," + BASE,
        "pinot.authz.mode=native",
        "pinot.authz.native.rules=analysts",
        "pinot.authz.native.rule.analysts.groups=analysts",
        "pinot.authz.native.rule.analysts.permissions=READ",
        "pinot.authz.native.rule.analysts.tables=orders"), StandardCharsets.UTF_8);
  }

  @AfterClass
  public void tearDown() {
    _server.shutDown(true);
  }

  private String run(String password, boolean expected, String tables)
      throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    LdapCheckCommand command = new LdapCheckCommand().setConfigFile(_config.getAbsolutePath()).setUser("alice")
        .setPasswordFile("-").setTables(tables).setOutput(new PrintStream(out, true, StandardCharsets.UTF_8))
        .setInput(new ByteArrayInputStream((password + "\n").getBytes(StandardCharsets.UTF_8)));
    assertTrue(command.execute() == expected);
    String output = out.toString(StandardCharsets.UTF_8);
    assertFalse(output.contains(ALICE_PASSWORD), output);
    assertFalse(output.contains(BIND_PASSWORD), output);
    return output;
  }

  @Test
  public void testAcceptedWithDecisions()
      throws Exception {
    String output = run(ALICE_PASSWORD, true, "orders,customers");
    assertTrue(output.contains("Result: ACCEPTED"), output);
    assertTrue(output.contains("user: alice"), output);
    assertTrue(output.contains("groups: [analysts]"), output);
    assertTrue(output.contains("dn: uid=alice,ou=people," + BASE), output);
    assertTrue(output.contains("Authorization (native mode"), output);
    assertTrue(output.contains("rule analysts"), output);
    // Settings print as the method reads them (a DN is one value, not a list)
    assertTrue(output.contains("bind.dn = cn=bind," + BASE), output);
  }

  @Test
  public void testRejected()
      throws Exception {
    String output = run("wrong-password", false, null);
    assertTrue(output.contains("Result: REJECTED (HTTP 401)"), output);
  }

  @Test
  public void testFileReadAsTheRolesReadIt()
      throws Exception {
    // A comma inside a DN value is written as \2C (ODP-8749); java.util.Properties would drop the backslash
    File file = File.createTempFile("ldap-check-escape", ".properties");
    file.deleteOnExit();
    Files.writeString(file.toPath(), "pinot.auth.ldap.bind.dn=CN=pinot-bind,OU=Service Accounts\\2C Pinot,DC=corp\n",
        StandardCharsets.UTF_8);
    assertEquals(AuthCheckSupport.readConfiguration(file.getAbsolutePath()).getProperty("pinot.auth.ldap.bind.dn"),
        "CN=pinot-bind,OU=Service Accounts\\2C Pinot,DC=corp");
  }

  @Test
  public void testOtherMethod()
      throws Exception {
    File other = File.createTempFile("ldap-check-other", ".properties");
    other.deleteOnExit();
    Files.writeString(other.toPath(), "pinot.auth.method=basic\n", StandardCharsets.UTF_8);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertFalse(new LdapCheckCommand().setConfigFile(other.getAbsolutePath()).setUser("alice")
        .setOutput(new PrintStream(out, true, StandardCharsets.UTF_8)).execute());
    assertTrue(out.toString(StandardCharsets.UTF_8).contains("this check needs ldap"));
  }
}
