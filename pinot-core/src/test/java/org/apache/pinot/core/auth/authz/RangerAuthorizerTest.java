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

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.plugin.auth.spi.AccessRequest;
import org.apache.pinot.plugin.auth.spi.AuthMethod;
import org.apache.pinot.plugin.auth.spi.AuthorizationDecision;
import org.apache.pinot.plugin.auth.spi.AuthorizerSelector;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.apache.pinot.plugin.auth.spi.PinotAuthorizer;
import org.apache.pinot.plugin.auth.spi.PinotPrincipal;
import org.apache.pinot.plugin.auth.spi.ResourceType;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;


/// The ranger authorizer against a stand-in for the Ranger plug-in that follows the PinotAccessChecker contract.
public class RangerAuthorizerTest {
  private static final PinotPrincipal ALICE =
      new PinotPrincipal("alice", Set.of("analysts"), AuthMethod.OAUTH2, false, Collections.emptyMap());

  @BeforeMethod
  public void reset() {
    FakeRangerPlugin.reset();
  }

  @Test
  public void testDecisionsAndArguments() {
    PinotAuthorizer authorizer = AuthorizerSelector.create(config("pinot.authz.mode", "ranger",
        "pinot.authz.ranger.plugin.class", FakeRangerPlugin.class.getName(),
        "pinot.authz.ranger.service.name", "pinotprod", "pinot.authz.ranger.config.dir", "/etc/pinot/conf"));
    assertTrue(authorizer instanceof RangerAuthorizer, "default class of the ranger mode");
    assertEquals(FakeRangerPlugin._settings, Map.of("service.name", "pinotprod", "config.dir", "/etc/pinot/conf"));

    AuthorizationDecision allowed = authorizer.authorize(ALICE,
        new AccessRequest(ResourceType.TABLE, "default", "orders", "GetTableConfig", Permission.READ, "read_metadata"));
    assertTrue(allowed.isAllowed());
    assertEquals(allowed.getReason(), "Ranger policy 7");
    assertEquals(FakeRangerPlugin._calls.get(0),
        List.of("alice", Set.of("analysts"), "TABLE", "default", "orders", "read_metadata", "GetTableConfig"));

    AuthorizationDecision denied = authorizer.authorize(ALICE,
        new AccessRequest(ResourceType.CLUSTER, null, null, "UpdateClusterConfig", Permission.UPDATE,
            "manage_cluster_config"));
    assertFalse(denied.isAllowed());
    assertEquals(denied.getReason(), "no Ranger policy allows manage_cluster_config");

    assertEquals(authorizer.getRowFilters(ALICE, "default", "orders"), List.of("region = 'south'"));
    assertEquals(authorizer.getRowFilters(ALICE, "default", "other"), List.of());

    authorizer.close();
    assertTrue(FakeRangerPlugin._closed);
  }

  @Test
  public void testPluginErrorsFailClosed() {
    RangerAuthorizer authorizer = new RangerAuthorizer();
    authorizer.init(config("plugin.class", FakeRangerPlugin.class.getName()));
    FakeRangerPlugin._fail = true;
    AuthorizationDecision decision = authorizer.authorize(ALICE,
        new AccessRequest(ResourceType.TABLE, "default", "orders", "Query", Permission.READ, "query"));
    assertFalse(decision.isAllowed());
    assertTrue(decision.getReason().contains("Ranger plug-in error"), decision.getReason());
    // Row filters cannot be decided: the query fails rather than returning unfiltered rows
    expectThrows(IllegalStateException.class, () -> authorizer.getRowFilters(ALICE, "default", "orders"));
  }

  @Test
  public void testMissingOrWrongPlugin() {
    IllegalStateException missing = expectThrows(IllegalStateException.class,
        () -> new RangerAuthorizer().init(config()));
    assertTrue(missing.getMessage().contains("Ranger plug-in for Pinot is not installed"), missing.getMessage());
    assertTrue(missing.getMessage().contains(RangerAuthorizer.DEFAULT_PLUGIN_CLASS), missing.getMessage());

    IllegalStateException wrong = expectThrows(IllegalStateException.class,
        () -> new RangerAuthorizer().init(config("plugin.class", String.class.getName())));
    assertTrue(wrong.getMessage().contains("is not a Ranger plug-in for Pinot"), wrong.getMessage());
  }

  private static PinotConfiguration config(String... keyValues) {
    Map<String, Object> map = new HashMap<>();
    for (int i = 0; i < keyValues.length; i += 2) {
      map.put(keyValues[i], keyValues[i + 1]);
    }
    return new PinotConfiguration(map);
  }

  /// Follows Ranger's PinotAccessChecker contract (JDK types only).
  public static class FakeRangerPlugin {
    static Map<String, String> _settings;
    static List<List<Object>> _calls = new ArrayList<>();
    static boolean _closed;
    static boolean _fail;

    static void reset() {
      _settings = null;
      _calls = new ArrayList<>();
      _closed = false;
      _fail = false;
    }

    public void init(Map<String, String> settings) {
      _settings = settings;
    }

    public Map.Entry<Boolean, String> checkAccess(String user, Set<String> groups, String resourceType,
        String database, String table, String accessType, String action) {
      if (_fail) {
        throw new IllegalStateException("policy engine not ready");
      }
      List<Object> call = new ArrayList<>();
      Collections.addAll(call, user, groups, resourceType, database, table, accessType, action);
      _calls.add(call);
      boolean allowed = "read_metadata".equals(accessType) && "orders".equals(table);
      return new AbstractMap.SimpleImmutableEntry<>(allowed,
          allowed ? "Ranger policy 7" : "no Ranger policy allows " + accessType);
    }

    public List<String> getRowFilters(String user, Set<String> groups, String database, String table) {
      if (_fail) {
        throw new IllegalStateException("policy engine not ready");
      }
      return "orders".equals(table) ? List.of("region = 'south'") : List.of();
    }

    public void close() {
      _closed = true;
    }
  }
}
