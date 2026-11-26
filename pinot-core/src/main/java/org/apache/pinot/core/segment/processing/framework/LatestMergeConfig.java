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
package org.apache.pinot.core.segment.processing.framework;

import com.google.common.base.Preconditions;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.apache.pinot.core.common.MinionConstants.MergeTask;
import org.apache.pinot.spi.data.FieldSpec;
import org.apache.pinot.spi.data.FieldSpec.DataType;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.data.readers.GenericRow;


/**
 * How a LATEST merge chooses the winning row, and the memory cap for the on-disk sort.
 * Immutable. Safe to share across partitions of one task.
 */
public final class LatestMergeConfig {
  public static final int DEFAULT_MAX_ROWS_IN_MEMORY = 100_000;
  public static final int DEFAULT_MAX_MERGE_FAN_IN = 16;

  private static final Set<DataType> COMPARABLE_TYPES =
      EnumSet.of(DataType.INT, DataType.LONG, DataType.FLOAT, DataType.DOUBLE, DataType.BOOLEAN, DataType.TIMESTAMP,
          DataType.STRING, DataType.BIG_DECIMAL);

  private final List<String> _primaryKeyColumns;
  private final List<FieldSpec> _primaryKeySpecs;
  private final String _versionColumn;
  private final FieldSpec _versionSpec;
  private final List<FieldSpec> _tieBreakSpecs;
  private final int _maxRowsInMemory;
  private final int _maxMergeFanIn;

  private LatestMergeConfig(List<String> primaryKeyColumns, List<FieldSpec> primaryKeySpecs, String versionColumn,
      FieldSpec versionSpec, List<FieldSpec> tieBreakSpecs, int maxRowsInMemory, int maxMergeFanIn) {
    _primaryKeyColumns = primaryKeyColumns;
    _primaryKeySpecs = primaryKeySpecs;
    _versionColumn = versionColumn;
    _versionSpec = versionSpec;
    _tieBreakSpecs = tieBreakSpecs;
    _maxRowsInMemory = maxRowsInMemory;
    _maxMergeFanIn = maxMergeFanIn;
  }

  /**
   * Reads and checks the LATEST task settings. Throws when the version column or primary key cannot be used.
   */
  public static LatestMergeConfig fromTaskConfig(Schema schema, Map<String, String> taskConfig) {
    Preconditions.checkNotNull(schema, "Schema is required for LATEST merge");
    String versionColumn = taskConfig.get(MergeTask.LATEST_VERSION_COLUMN_KEY);
    Preconditions.checkState(versionColumn != null && !versionColumn.trim().isEmpty(),
        "%s is required when mergeType is LATEST", MergeTask.LATEST_VERSION_COLUMN_KEY);
    versionColumn = versionColumn.trim();
    FieldSpec versionSpec = requireComparableColumn(schema, versionColumn, "version");

    List<String> primaryKeyColumns = readPrimaryKeyColumns(schema, taskConfig);
    Preconditions.checkState(!primaryKeyColumns.isEmpty(),
        "Primary key is empty. Set %s or a schema primary key.", MergeTask.LATEST_PRIMARY_KEY_COLUMNS_KEY);
    List<FieldSpec> primaryKeySpecs = new ArrayList<>(primaryKeyColumns.size());
    for (String column : primaryKeyColumns) {
      primaryKeySpecs.add(requireComparableColumn(schema, column, "primary key"));
    }

    List<FieldSpec> tieBreakSpecs = new ArrayList<>();
    for (FieldSpec fieldSpec : schema.getAllFieldSpecs()) {
      if (fieldSpec.isVirtualColumn() || !fieldSpec.isSingleValueField()) {
        continue;
      }
      String name = fieldSpec.getName();
      if (name.equals(versionColumn) || primaryKeyColumns.contains(name)) {
        continue;
      }
      if (COMPARABLE_TYPES.contains(fieldSpec.getDataType())) {
        tieBreakSpecs.add(fieldSpec);
      }
    }
    tieBreakSpecs.sort((left, right) -> left.getName().compareTo(right.getName()));

    int maxRowsInMemory = readPositiveInt(taskConfig, MergeTask.LATEST_MAX_ROWS_IN_MEMORY_KEY,
        DEFAULT_MAX_ROWS_IN_MEMORY);
    int maxMergeFanIn =
        readPositiveInt(taskConfig, MergeTask.LATEST_MAX_MERGE_FAN_IN_KEY, DEFAULT_MAX_MERGE_FAN_IN);
    Preconditions.checkState(maxMergeFanIn >= 2, "%s must be at least 2, got %s",
        MergeTask.LATEST_MAX_MERGE_FAN_IN_KEY, maxMergeFanIn);

    return new LatestMergeConfig(Collections.unmodifiableList(primaryKeyColumns),
        Collections.unmodifiableList(primaryKeySpecs), versionColumn, versionSpec,
        Collections.unmodifiableList(tieBreakSpecs), maxRowsInMemory, maxMergeFanIn);
  }

  public List<String> getPrimaryKeyColumns() {
    return _primaryKeyColumns;
  }

  public String getVersionColumn() {
    return _versionColumn;
  }

  public int getMaxRowsInMemory() {
    return _maxRowsInMemory;
  }

  public int getMaxMergeFanIn() {
    return _maxMergeFanIn;
  }

  /**
   * Compares two rows in ascending order: primary key, then version, then tie-break columns.
   * A null is older than any real value, so a null version sorts first and loses when the newest row is kept.
   */
  public int compare(GenericRow left, GenericRow right) {
    for (FieldSpec fieldSpec : _primaryKeySpecs) {
      int result = compareColumn(left, right, fieldSpec);
      if (result != 0) {
        return result;
      }
    }
    int versionCompare = compareColumn(left, right, _versionSpec);
    if (versionCompare != 0) {
      return versionCompare;
    }
    for (FieldSpec fieldSpec : _tieBreakSpecs) {
      int result = compareColumn(left, right, fieldSpec);
      if (result != 0) {
        return result;
      }
    }
    return 0;
  }

  /**
   * Returns {@code true} when both rows have the same primary key, including nulls.
   */
  public boolean samePrimaryKey(GenericRow left, GenericRow right) {
    for (FieldSpec fieldSpec : _primaryKeySpecs) {
      if (compareColumn(left, right, fieldSpec) != 0) {
        return false;
      }
    }
    return true;
  }

  private static List<String> readPrimaryKeyColumns(Schema schema, Map<String, String> taskConfig) {
    String configured = taskConfig.get(MergeTask.LATEST_PRIMARY_KEY_COLUMNS_KEY);
    if (configured != null && !configured.trim().isEmpty()) {
      List<String> columns = new ArrayList<>();
      for (String part : configured.split(",")) {
        String column = part.trim();
        if (!column.isEmpty()) {
          columns.add(column);
        }
      }
      return columns;
    }
    List<String> schemaPrimaryKey = schema.getPrimaryKeyColumns();
    if (schemaPrimaryKey == null) {
      return Collections.emptyList();
    }
    return new ArrayList<>(schemaPrimaryKey);
  }

  private static FieldSpec requireComparableColumn(Schema schema, String column, String role) {
    FieldSpec fieldSpec = schema.getFieldSpecFor(column);
    Preconditions.checkState(fieldSpec != null, "%s column %s does not exist in the schema",
        capitalize(role), column);
    Preconditions.checkState(fieldSpec.isSingleValueField(),
        "%s column %s must be a single-value column", capitalize(role), column);
    Preconditions.checkState(!fieldSpec.isVirtualColumn(), "%s column %s must not be a virtual column",
        capitalize(role), column);
    Preconditions.checkState(COMPARABLE_TYPES.contains(fieldSpec.getDataType()),
        "%s column %s of type %s is not supported. Supported types: %s", capitalize(role), column,
        fieldSpec.getDataType(), COMPARABLE_TYPES);
    return fieldSpec;
  }

  private static int readPositiveInt(Map<String, String> taskConfig, String key, int defaultValue) {
    String value = taskConfig.get(key);
    if (value == null || value.trim().isEmpty()) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      Preconditions.checkState(parsed > 0, "%s must be a positive integer, got %s", key, value);
      return parsed;
    } catch (NumberFormatException e) {
      throw new IllegalStateException(key + " must be a positive integer, got " + value, e);
    }
  }

  private static String capitalize(String value) {
    if (value.isEmpty()) {
      return value;
    }
    return value.substring(0, 1).toUpperCase(Locale.ROOT) + value.substring(1);
  }

  private static int compareColumn(GenericRow left, GenericRow right, FieldSpec fieldSpec) {
    String column = fieldSpec.getName();
    boolean leftNull = isNull(left, column);
    boolean rightNull = isNull(right, column);
    if (leftNull && rightNull) {
      return 0;
    }
    if (leftNull) {
      return -1;
    }
    if (rightNull) {
      return 1;
    }
    Object leftValue = left.getValue(column);
    Object rightValue = right.getValue(column);
    switch (fieldSpec.getDataType().getStoredType()) {
      case INT:
      case LONG:
        return Long.compare(toLong(leftValue), toLong(rightValue));
      case FLOAT:
        return Float.compare(toFloat(leftValue), toFloat(rightValue));
      case DOUBLE:
        return Double.compare(toDouble(leftValue), toDouble(rightValue));
      case BIG_DECIMAL:
        return toBigDecimal(leftValue).compareTo(toBigDecimal(rightValue));
      case STRING:
        return String.valueOf(leftValue).compareTo(String.valueOf(rightValue));
      default:
        throw new IllegalStateException("Cannot compare column " + column + " of type " + fieldSpec.getDataType());
    }
  }

  private static boolean isNull(GenericRow row, String column) {
    return row.isNullValue(column) || row.getValue(column) == null;
  }

  private static long toLong(Object value) {
    if (value instanceof Boolean) {
      return (Boolean) value ? 1L : 0L;
    }
    if (value instanceof Number) {
      return ((Number) value).longValue();
    }
    return Long.parseLong(String.valueOf(value));
  }

  private static float toFloat(Object value) {
    return value instanceof Number ? ((Number) value).floatValue() : Float.parseFloat(String.valueOf(value));
  }

  private static double toDouble(Object value) {
    return value instanceof Number ? ((Number) value).doubleValue() : Double.parseDouble(String.valueOf(value));
  }

  private static BigDecimal toBigDecimal(Object value) {
    if (value instanceof BigDecimal) {
      return (BigDecimal) value;
    }
    if (value instanceof Number) {
      return new BigDecimal(value.toString());
    }
    return new BigDecimal(String.valueOf(value));
  }
}
