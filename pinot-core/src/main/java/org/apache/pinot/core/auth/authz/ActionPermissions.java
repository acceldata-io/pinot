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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.plugin.auth.spi.Permission;


/// Maps every fine-grained action of [Actions] to the native [Permission] it requires and to the access type used by
/// external authorizers (the Ranger service definition for Pinot). An action that is not in the map is denied: a new
/// action must be added here, which `ActionPermissionsTest` enforces for every constant of [Actions]. Immutable.
///
/// Access types: `query`, `read_metadata`, `manage_table`, `manage_segments`, `manage_ingestion`, `rebalance`,
/// `manage_tasks`, `manage_quotas`, `manage_database`, `manage_queries`, `manage_tenants_instances`,
/// `manage_cluster_config`, `manage_zookeeper`, `manage_users`. Reads of metadata need `READ`; changes need `CREATE`,
/// `UPDATE` or `DELETE` by what they do; ZooKeeper and user management need `ADMIN`. `GetAuth` (the UI sign-in check)
/// only needs an authenticated principal. `DownloadSegment` needs `READ`, but exposes raw rows: authorizers must not
/// grant it to principals restricted by row filters.
public final class ActionPermissions {
  /// The requirement of one action.
  public static final class Requirement {
    @Nullable
    private final Permission _permission;
    @Nullable
    private final String _accessType;

    private Requirement(@Nullable Permission permission, @Nullable String accessType) {
      _permission = permission;
      _accessType = accessType;
    }

    /// Whether any authenticated principal may perform the action.
    public boolean isAuthenticatedOnly() {
      return _permission == null;
    }

    /// @return the native permission, `null` when [#isAuthenticatedOnly()]
    @Nullable
    public Permission getPermission() {
      return _permission;
    }

    /// @return the external access type, `null` when [#isAuthenticatedOnly()]
    @Nullable
    public String getAccessType() {
      return _accessType;
    }
  }

  private static final Map<TargetType, Map<String, Requirement>> REQUIREMENTS = new HashMap<>();

  static {
    for (TargetType targetType : TargetType.values()) {
      REQUIREMENTS.put(targetType, new HashMap<>());
    }
    // Cluster actions
    put(TargetType.CLUSTER, Actions.Cluster.CANCEL_QUERY, Permission.UPDATE, "manage_queries");
    put(TargetType.CLUSTER, Actions.Cluster.CLEANUP_TASK, Permission.UPDATE, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.COMMIT_SEGMENT, Permission.CREATE, "manage_segments");
    put(TargetType.CLUSTER, Actions.Cluster.CREATE_INSTANCE, Permission.CREATE, "manage_tenants_instances");
    put(TargetType.CLUSTER, Actions.Cluster.CREATE_TASK, Permission.UPDATE, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.CREATE_TENANT, Permission.CREATE, "manage_tenants_instances");
    put(TargetType.CLUSTER, Actions.Cluster.CREATE_USER, Permission.ADMIN, "manage_users");
    put(TargetType.CLUSTER, Actions.Cluster.DEBUG_RESOURCE_USAGE, Permission.UPDATE, "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.DEBUG_TASK, Permission.UPDATE, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_CLUSTER_CONFIG, Permission.UPDATE, "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_DATABASE, Permission.DELETE, "manage_database");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_INSTANCE, Permission.DELETE, "manage_tenants_instances");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_QUERY_WORKLOAD_CONFIG, Permission.UPDATE, "manage_queries");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_RESPONSE_STORE, Permission.UPDATE, "manage_queries");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_TASK, Permission.UPDATE, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_TENANT, Permission.DELETE, "manage_tenants_instances");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_USER, Permission.ADMIN, "manage_users");
    put(TargetType.CLUSTER, Actions.Cluster.DELETE_ZNODE, Permission.ADMIN, "manage_zookeeper");
    put(TargetType.CLUSTER, Actions.Cluster.ESTIMATE_UPSERT_MEMORY, Permission.READ, "manage_table");
    put(TargetType.CLUSTER, Actions.Cluster.EXECUTE_TASK, Permission.UPDATE, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.GET_ADMIN_INFO, Permission.READ, "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.GET_APPLICATION_QUERY_QUOTA, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_APP_CONFIG, Permission.READ, "manage_cluster_config");
    authenticatedOnly(TargetType.CLUSTER, Actions.Cluster.GET_AUTH);
    put(TargetType.CLUSTER, Actions.Cluster.GET_BROKER, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_CLUSTER_CONFIG, Permission.READ, "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.GET_DATABASE, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_DATABASE_QUERY_QUOTA, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_DATABASE_QUOTA, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_FORCE_COMMIT_STATUS, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_GROOVY_STATIC_ANALYZER_CONFIG, Permission.READ,
        "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.GET_HEALTH, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_INSTANCE, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_INSTANCE_PARTITIONS, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_INSTANCE_QUERY_WORKLOAD_CONFIG, Permission.READ, "manage_queries");
    put(TargetType.CLUSTER, Actions.Cluster.GET_LOGGER, Permission.READ, "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.GET_LOG_FILE, Permission.READ, "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.GET_QUERY_WORKLOAD_CONFIG, Permission.READ, "manage_queries");
    put(TargetType.CLUSTER, Actions.Cluster.GET_REBALANCE_STATUS, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_RESPONSE_STORE, Permission.READ, "manage_queries");
    put(TargetType.CLUSTER, Actions.Cluster.GET_RUNNING_QUERY, Permission.READ, "manage_queries");
    put(TargetType.CLUSTER, Actions.Cluster.GET_SCHEDULER_INFO, Permission.READ, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.GET_SCHEMA, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_SCHEMAS_INFO, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_SEGMENT, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_SEGMENT_RELOAD_STATUS, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_SERVER_ROUTING_STATS, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_TABLE, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_TABLE_CONFIG, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_TABLE_LEADER, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_TASK, Permission.READ, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.GET_TASK_COUNT, Permission.READ, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.GET_TENANT, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_USER, Permission.ADMIN, "manage_users");
    put(TargetType.CLUSTER, Actions.Cluster.GET_VERSION, Permission.READ, "read_metadata");
    put(TargetType.CLUSTER, Actions.Cluster.GET_ZNODE, Permission.ADMIN, "manage_zookeeper");
    put(TargetType.CLUSTER, Actions.Cluster.INGEST_FILE, Permission.UPDATE, "manage_ingestion");
    put(TargetType.CLUSTER, Actions.Cluster.REBALANCE_TENANT_TABLES, Permission.UPDATE, "manage_tenants_instances");
    put(TargetType.CLUSTER, Actions.Cluster.RECOMMEND_CONFIG, Permission.READ, "manage_table");
    put(TargetType.CLUSTER, Actions.Cluster.RESET_SEGMENT, Permission.UPDATE, "manage_segments");
    put(TargetType.CLUSTER, Actions.Cluster.RESUME_TASK, Permission.UPDATE, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.STOP_TASK, Permission.UPDATE, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_APPLICATION_QUOTA, Permission.UPDATE, "manage_quotas");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_BROKER_RESOURCE, Permission.UPDATE, "rebalance");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_CLUSTER_CONFIG, Permission.UPDATE, "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_DATABASE_QUOTA, Permission.UPDATE, "manage_quotas");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_GROOVY_STATIC_ANALYZER_CONFIG, Permission.UPDATE,
        "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_INSTANCE, Permission.UPDATE, "manage_tenants_instances");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_INSTANCE_PARTITIONS, Permission.UPDATE, "rebalance");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_LOGGER, Permission.UPDATE, "manage_cluster_config");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_QPS, Permission.UPDATE, "manage_quotas");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_QUERY_WORKLOAD_CONFIG, Permission.UPDATE, "manage_queries");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_TASK_QUEUE, Permission.UPDATE, "manage_tasks");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_TENANT, Permission.UPDATE, "manage_tenants_instances");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_TENANT_METADATA, Permission.UPDATE, "manage_tenants_instances");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_TIME_INTERVAL, Permission.UPDATE, "manage_segments");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_USER, Permission.ADMIN, "manage_users");
    put(TargetType.CLUSTER, Actions.Cluster.UPDATE_ZNODE, Permission.ADMIN, "manage_zookeeper");
    put(TargetType.CLUSTER, Actions.Cluster.UPLOAD_SEGMENT, Permission.CREATE, "manage_segments");

    // Database actions
    put(TargetType.DATABASE, Actions.Database.DELETE_DATABASE, Permission.DELETE, "manage_database");
    put(TargetType.DATABASE, Actions.Database.GET_DATABASE_QUERY_QUOTA, Permission.READ, "read_metadata");
    put(TargetType.DATABASE, Actions.Database.GET_DATABASE_QUOTA, Permission.READ, "read_metadata");
    put(TargetType.DATABASE, Actions.Database.UPDATE_DATABASE_QUOTA, Permission.UPDATE, "manage_quotas");

    // Table actions
    put(TargetType.TABLE, Actions.Table.BUILD_ROUTING, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.CANCEL_REBALANCE, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.CREATE_INSTANCE_PARTITIONS, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.CREATE_SCHEMA, Permission.CREATE, "manage_table");
    put(TargetType.TABLE, Actions.Table.CREATE_TABLE, Permission.CREATE, "manage_table");
    put(TargetType.TABLE, Actions.Table.DELETE_INGESTION_METRICS, Permission.UPDATE, "manage_ingestion");
    put(TargetType.TABLE, Actions.Table.DELETE_INSTANCE_PARTITIONS, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.DELETE_ROUTING, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.DELETE_SCHEMA, Permission.DELETE, "manage_table");
    put(TargetType.TABLE, Actions.Table.DELETE_SEGMENT, Permission.DELETE, "manage_segments");
    put(TargetType.TABLE, Actions.Table.DELETE_TABLE, Permission.DELETE, "manage_table");
    put(TargetType.TABLE, Actions.Table.DELETE_TIME_BOUNDARY, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.DISABLE_TABLE, Permission.UPDATE, "manage_table");
    put(TargetType.TABLE, Actions.Table.DOWNLOAD_SEGMENT, Permission.READ, "manage_segments");
    put(TargetType.TABLE, Actions.Table.ENABLE_TABLE, Permission.UPDATE, "manage_table");
    put(TargetType.TABLE, Actions.Table.FORCE_COMMIT, Permission.UPDATE, "manage_ingestion");
    put(TargetType.TABLE, Actions.Table.FORCE_RELEASE_TASK_GENERATION_LOCK, Permission.UPDATE, "manage_tasks");
    put(TargetType.TABLE, Actions.Table.GET_BROKER, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_CONSUMING_SEGMENTS, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_CONTROLLER_JOBS, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_DEBUG_INFO, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_EXTERNAL_VIEW, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_IDEAL_STATE, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_INSTANCE, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_INSTANCE_PARTITIONS, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_METADATA, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_PAUSE_STATUS, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_ROUTING_TABLE, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_SCHEDULER_JOB_DETAILS, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_SCHEMA, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_SEGMENT, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_SEGMENT_LINEAGE, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_SEGMENT_MAP, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_SEGMENT_STATUS, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_SERVER_MAP, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_SIZE, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_STATE, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_STORAGE_TIER, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_TABLE_CONFIG, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_TABLE_CONFIGS, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_TABLE_LEADER, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_TABLE_QUERY_QUOTA, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.GET_TIME_BOUNDARY, Permission.READ, "read_metadata");
    put(TargetType.TABLE, Actions.Table.PAUSE_CONSUMPTION, Permission.UPDATE, "manage_ingestion");
    put(TargetType.TABLE, Actions.Table.QUERY, Permission.READ, "query");
    put(TargetType.TABLE, Actions.Table.REBALANCE_TABLE, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.REBUILD_BROKER_RESOURCE, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.REFRESH_ROUTING, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.RELOAD_SEGMENT, Permission.UPDATE, "manage_segments");
    put(TargetType.TABLE, Actions.Table.REPLACE_SEGMENT, Permission.UPDATE, "manage_segments");
    put(TargetType.TABLE, Actions.Table.RESUME_CONSUMPTION, Permission.UPDATE, "manage_ingestion");
    put(TargetType.TABLE, Actions.Table.UPDATE_INSTANCE_PARTITIONS, Permission.UPDATE, "rebalance");
    put(TargetType.TABLE, Actions.Table.UPDATE_SCHEMA, Permission.UPDATE, "manage_table");
    put(TargetType.TABLE, Actions.Table.UPDATE_TABLE_CONFIG, Permission.UPDATE, "manage_table");
    put(TargetType.TABLE, Actions.Table.UPDATE_TABLE_CONFIGS, Permission.UPDATE, "manage_table");
    put(TargetType.TABLE, Actions.Table.UPLOAD_SEGMENT, Permission.CREATE, "manage_segments");
    put(TargetType.TABLE, Actions.Table.VALIDATE_SCHEMA, Permission.READ, "manage_table");
    put(TargetType.TABLE, Actions.Table.VALIDATE_TABLE_CONFIGS, Permission.READ, "manage_table");
  }

  private ActionPermissions() {
  }

  private static void put(TargetType targetType, String action, Permission permission, String accessType) {
    if (REQUIREMENTS.get(targetType).put(action, new Requirement(permission, accessType)) != null) {
      throw new IllegalStateException("Action " + action + " mapped twice for " + targetType);
    }
  }

  private static void authenticatedOnly(TargetType targetType, String action) {
    REQUIREMENTS.get(targetType).put(action, new Requirement(null, null));
  }

  /// @return the requirement of the action, or `null` for an unknown action (which must be denied)
  @Nullable
  public static Requirement get(TargetType targetType, String action) {
    return REQUIREMENTS.get(Objects.requireNonNull(targetType, "targetType")).get(action);
  }
}
