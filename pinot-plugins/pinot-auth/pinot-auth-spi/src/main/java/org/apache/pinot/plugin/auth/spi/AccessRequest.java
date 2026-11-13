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
package org.apache.pinot.plugin.auth.spi;

import java.util.Objects;
import javax.annotation.Nullable;


/// What a principal asks to do: a resource (cluster, database or table), the fine-grained action when the endpoint
/// declares one, and that action's mapping to a native [Permission] and to an access type of external authorizers
/// (for example Ranger). Immutable.
public final class AccessRequest {
  private final ResourceType _resourceType;
  @Nullable
  private final String _database;
  @Nullable
  private final String _table;
  @Nullable
  private final String _action;
  private final Permission _permission;
  private final String _accessType;

  /// @param database for `TABLE` and `DATABASE`; `default` when the name carries no database
  /// @param table for `TABLE`: the raw table name, without database and without type suffix
  /// @param action the fine-grained action, or `null` for a coarse check
  public AccessRequest(ResourceType resourceType, @Nullable String database, @Nullable String table,
      @Nullable String action, Permission permission, String accessType) {
    _resourceType = Objects.requireNonNull(resourceType, "resourceType");
    _database = database;
    _table = table;
    _action = action;
    _permission = Objects.requireNonNull(permission, "permission");
    _accessType = Objects.requireNonNull(accessType, "accessType");
    if (resourceType == ResourceType.TABLE && (database == null || table == null)) {
      throw new IllegalArgumentException("A table request needs a database and a table");
    }
    if (resourceType == ResourceType.DATABASE && database == null) {
      throw new IllegalArgumentException("A database request needs a database");
    }
    if (permission == Permission.ALL) {
      throw new IllegalArgumentException("ALL is granted, never required");
    }
  }

  public ResourceType getResourceType() {
    return _resourceType;
  }

  @Nullable
  public String getDatabase() {
    return _database;
  }

  @Nullable
  public String getTable() {
    return _table;
  }

  @Nullable
  public String getAction() {
    return _action;
  }

  public Permission getPermission() {
    return _permission;
  }

  public String getAccessType() {
    return _accessType;
  }

  /// `cluster`, `<database>` or `<database>.<table>`.
  public String describeResource() {
    switch (_resourceType) {
      case TABLE:
        return _database + "." + _table;
      case DATABASE:
        return _database;
      default:
        return "cluster";
    }
  }

  @Override
  public String toString() {
    return (_action != null ? _action : _permission.name()) + " on " + describeResource();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof AccessRequest)) {
      return false;
    }
    AccessRequest that = (AccessRequest) o;
    return _resourceType == that._resourceType && Objects.equals(_database, that._database) && Objects.equals(_table,
        that._table) && Objects.equals(_action, that._action) && _permission == that._permission
        && _accessType.equals(that._accessType);
  }

  @Override
  public int hashCode() {
    return Objects.hash(_resourceType, _database, _table, _action, _permission, _accessType);
  }
}
