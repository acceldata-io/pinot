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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.plugin.auth.spi.Permission;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;


/// Every action in [Actions] must have a requirement in [ActionPermissions]; a new action without one would be denied
/// to everybody, so this test fails first.
public class ActionPermissionsTest {
  private static final List<String> ACCESS_TYPES = List.of("query", "read_metadata", "manage_table",
      "manage_segments", "manage_ingestion", "rebalance", "manage_tasks", "manage_quotas", "manage_database",
      "manage_queries", "manage_tenants_instances", "manage_cluster_config", "manage_zookeeper", "manage_users");

  @Test
  public void testEveryActionIsMapped()
      throws IllegalAccessException {
    List<String> missing = new ArrayList<>();
    int checked = 0;
    for (Object[] scope : new Object[][]{
        {Actions.Cluster.class, TargetType.CLUSTER}, {Actions.Database.class, TargetType.DATABASE},
        {Actions.Table.class, TargetType.TABLE}}) {
      for (Field field : ((Class<?>) scope[0]).getFields()) {
        if (!Modifier.isStatic(field.getModifiers()) || field.getType() != String.class) {
          continue;
        }
        String action = (String) field.get(null);
        ActionPermissions.Requirement requirement = ActionPermissions.get((TargetType) scope[1], action);
        checked++;
        if (requirement == null) {
          missing.add(scope[1] + ":" + action);
        } else if (!requirement.isAuthenticatedOnly()) {
          assertTrue(ACCESS_TYPES.contains(requirement.getAccessType()), action + " -> " + requirement.getAccessType());
          assertTrue(requirement.getPermission() != Permission.ALL, action);
        }
      }
    }
    assertEquals(missing, List.of(), "Actions without a permission mapping");
    assertEquals(checked, 141);
  }

  @Test
  public void testRepresentativeMappings() {
    assertRequirement(TargetType.TABLE, Actions.Table.QUERY, Permission.READ, "query");
    assertRequirement(TargetType.TABLE, Actions.Table.GET_SCHEMA, Permission.READ, "read_metadata");
    assertRequirement(TargetType.TABLE, Actions.Table.DELETE_TABLE, Permission.DELETE, "manage_table");
    assertRequirement(TargetType.TABLE, Actions.Table.UPLOAD_SEGMENT, Permission.CREATE, "manage_segments");
    assertRequirement(TargetType.TABLE, Actions.Table.DOWNLOAD_SEGMENT, Permission.READ, "manage_segments");
    assertRequirement(TargetType.CLUSTER, Actions.Cluster.UPDATE_ZNODE, Permission.ADMIN, "manage_zookeeper");
    assertRequirement(TargetType.CLUSTER, Actions.Cluster.CREATE_USER, Permission.ADMIN, "manage_users");
    assertRequirement(TargetType.DATABASE, Actions.Database.DELETE_DATABASE, Permission.DELETE, "manage_database");
    // Shared action names resolve by target type
    assertNotNull(ActionPermissions.get(TargetType.CLUSTER, Actions.Cluster.UPLOAD_SEGMENT));
    assertTrue(ActionPermissions.get(TargetType.CLUSTER, Actions.Cluster.GET_AUTH).isAuthenticatedOnly());
    assertNull(ActionPermissions.get(TargetType.TABLE, "NotAnAction"));
    assertNull(ActionPermissions.get(TargetType.TABLE, Actions.Cluster.CREATE_USER));
  }

  private static void assertRequirement(TargetType targetType, String action, Permission permission,
      String accessType) {
    ActionPermissions.Requirement requirement = ActionPermissions.get(targetType, action);
    assertNotNull(requirement, action);
    assertEquals(requirement.getPermission(), permission, action);
    assertEquals(requirement.getAccessType(), accessType, action);
  }
}
