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
package org.apache.pinot.segment.local.rocksdb;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.apache.pinot.segment.local.upsert.ComparisonColumns;
import org.apache.pinot.spi.data.readers.PrimaryKey;
import org.apache.pinot.spi.utils.BigDecimalUtils;
import org.apache.pinot.spi.utils.ByteArray;


/**
 * Byte encodings of the keys and values kept in the RocksDB metadata stores.
 *
 * <ul>
 *   <li>Key: the primary key after {@code HashUtils.hashPrimaryKey}. A hashed key ({@link ByteArray}, e.g. 16 bytes
 *   for MURMUR3) is stored as-is; an unhashed {@link PrimaryKey} is stored as {@link PrimaryKey#asBytes()}, which is
 *   unique within a table because the key column types are fixed by the schema.</li>
 *   <li>Upsert value: segment id (4 bytes), doc id (4 bytes), then the comparison value with a 1-byte type tag.</li>
 *   <li>Dedup value: segment id (4 bytes), then the dedup time as a double (8 bytes).</li>
 * </ul>
 *
 * <p>The encoding is local to one server process: stores are rebuilt from segments on every start, so it is never
 * read by another version. Stateless and thread-safe.
 */
@SuppressWarnings("rawtypes")
public final class MetadataCodec {
  private static final byte NULL = 0;
  private static final byte INT = 1;
  private static final byte LONG = 2;
  private static final byte FLOAT = 3;
  private static final byte DOUBLE = 4;
  private static final byte STRING = 5;
  private static final byte BIG_DECIMAL = 6;
  private static final byte BYTES = 7;
  private static final byte COMPARISON_COLUMNS = 8;

  public static final int DEDUP_VALUE_SIZE = Integer.BYTES + Double.BYTES;

  private MetadataCodec() {
  }

  public static byte[] encodeKey(Object hashedPrimaryKey) {
    if (hashedPrimaryKey instanceof ByteArray) {
      return ((ByteArray) hashedPrimaryKey).getBytes();
    }
    if (hashedPrimaryKey instanceof PrimaryKey) {
      return ((PrimaryKey) hashedPrimaryKey).asBytes();
    }
    throw new IllegalStateException("Unsupported primary key type: " + hashedPrimaryKey.getClass());
  }

  public static byte[] encodeUpsertValue(int segmentId, int docId, Comparable comparisonValue) {
    ByteBuffer buffer = ByteBuffer.allocate(2 * Integer.BYTES + comparisonSize(comparisonValue));
    buffer.putInt(segmentId);
    buffer.putInt(docId);
    putComparison(buffer, comparisonValue);
    return buffer.array();
  }

  public static int decodeSegmentId(byte[] value) {
    return ((value[0] & 0xFF) << 24) | ((value[1] & 0xFF) << 16) | ((value[2] & 0xFF) << 8) | (value[3] & 0xFF);
  }

  public static int decodeDocId(byte[] upsertValue) {
    return ((upsertValue[4] & 0xFF) << 24) | ((upsertValue[5] & 0xFF) << 16) | ((upsertValue[6] & 0xFF) << 8)
        | (upsertValue[7] & 0xFF);
  }

  public static Comparable decodeComparisonValue(byte[] upsertValue) {
    ByteBuffer buffer = ByteBuffer.wrap(upsertValue, 2 * Integer.BYTES, upsertValue.length - 2 * Integer.BYTES);
    return getComparison(buffer);
  }

  public static byte[] encodeDedupValue(int segmentId, double dedupTime) {
    return ByteBuffer.allocate(DEDUP_VALUE_SIZE).putInt(segmentId).putDouble(dedupTime).array();
  }

  public static double decodeDedupTime(byte[] dedupValue) {
    return ByteBuffer.wrap(dedupValue).getDouble(Integer.BYTES);
  }

  private static int comparisonSize(Comparable value) {
    if (value == null) {
      return 1;
    }
    if (value instanceof Integer || value instanceof Float) {
      return 1 + Integer.BYTES;
    }
    if (value instanceof Long || value instanceof Double) {
      return 1 + Long.BYTES;
    }
    if (value instanceof String) {
      return 1 + Integer.BYTES + ((String) value).getBytes(StandardCharsets.UTF_8).length;
    }
    if (value instanceof BigDecimal) {
      return 1 + Integer.BYTES + BigDecimalUtils.byteSize((BigDecimal) value);
    }
    if (value instanceof ByteArray) {
      return 1 + Integer.BYTES + ((ByteArray) value).length();
    }
    if (value instanceof ComparisonColumns) {
      int size = 1 + 2 * Integer.BYTES;
      for (Comparable element : ((ComparisonColumns) value).getValues()) {
        size += comparisonSize(element);
      }
      return size;
    }
    throw new IllegalStateException("Unsupported comparison value type: " + value.getClass());
  }

  private static void putComparison(ByteBuffer buffer, Comparable value) {
    if (value == null) {
      buffer.put(NULL);
    } else if (value instanceof Integer) {
      buffer.put(INT).putInt((Integer) value);
    } else if (value instanceof Long) {
      buffer.put(LONG).putLong((Long) value);
    } else if (value instanceof Float) {
      buffer.put(FLOAT).putFloat((Float) value);
    } else if (value instanceof Double) {
      buffer.put(DOUBLE).putDouble((Double) value);
    } else if (value instanceof String) {
      byte[] bytes = ((String) value).getBytes(StandardCharsets.UTF_8);
      buffer.put(STRING).putInt(bytes.length).put(bytes);
    } else if (value instanceof BigDecimal) {
      byte[] bytes = BigDecimalUtils.serialize((BigDecimal) value);
      buffer.put(BIG_DECIMAL).putInt(bytes.length).put(bytes);
    } else if (value instanceof ByteArray) {
      byte[] bytes = ((ByteArray) value).getBytes();
      buffer.put(BYTES).putInt(bytes.length).put(bytes);
    } else if (value instanceof ComparisonColumns) {
      ComparisonColumns comparisonColumns = (ComparisonColumns) value;
      Comparable[] values = comparisonColumns.getValues();
      buffer.put(COMPARISON_COLUMNS).putInt(comparisonColumns.getComparableIndex()).putInt(values.length);
      for (Comparable element : values) {
        putComparison(buffer, element);
      }
    } else {
      throw new IllegalStateException("Unsupported comparison value type: " + value.getClass());
    }
  }

  private static Comparable getComparison(ByteBuffer buffer) {
    byte type = buffer.get();
    switch (type) {
      case NULL:
        return null;
      case INT:
        return buffer.getInt();
      case LONG:
        return buffer.getLong();
      case FLOAT:
        return buffer.getFloat();
      case DOUBLE:
        return buffer.getDouble();
      case STRING:
        return new String(getBytes(buffer), StandardCharsets.UTF_8);
      case BIG_DECIMAL:
        return BigDecimalUtils.deserialize(getBytes(buffer));
      case BYTES:
        return new ByteArray(getBytes(buffer));
      case COMPARISON_COLUMNS:
        int comparableIndex = buffer.getInt();
        Comparable[] values = new Comparable[buffer.getInt()];
        for (int i = 0; i < values.length; i++) {
          values[i] = getComparison(buffer);
        }
        return new ComparisonColumns(values, comparableIndex);
      default:
        throw new IllegalStateException("Unknown comparison value type tag: " + type);
    }
  }

  private static byte[] getBytes(ByteBuffer buffer) {
    byte[] bytes = new byte[buffer.getInt()];
    buffer.get(bytes);
    return bytes;
  }
}
