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
import java.nio.charset.StandardCharsets;
import org.apache.pinot.segment.local.upsert.ComparisonColumns;
import org.apache.pinot.segment.local.utils.HashUtils;
import org.apache.pinot.spi.config.table.HashFunction;
import org.apache.pinot.spi.data.readers.PrimaryKey;
import org.apache.pinot.spi.utils.ByteArray;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;


@SuppressWarnings("rawtypes")
public class MetadataCodecTest {

  @DataProvider
  public Object[][] comparisonValues() {
    return new Object[][]{
        {1_700_000_000}, {1_700_000_000_123L}, {1.5f}, {2.25d}, {"2026-11-12T10:00:00Z"},
        {new BigDecimal("12345.6789")}, {new ByteArray(new byte[]{1, 2, 3})},
        {new ComparisonColumns(new Comparable[]{null, 5L, "x"}, 1)},
        {new ComparisonColumns(new Comparable[]{3, null}, ComparisonColumns.SEALED_SEGMENT_COMPARISON_INDEX)}
    };
  }

  @Test(dataProvider = "comparisonValues")
  public void testUpsertValueRoundTrip(Comparable comparisonValue) {
    byte[] value = MetadataCodec.encodeUpsertValue(7, 123_456, comparisonValue);
    assertEquals(MetadataCodec.decodeSegmentId(value), 7);
    assertEquals(MetadataCodec.decodeDocId(value), 123_456);
    Comparable decoded = MetadataCodec.decodeComparisonValue(value);
    if (comparisonValue instanceof ComparisonColumns) {
      ComparisonColumns expected = (ComparisonColumns) comparisonValue;
      ComparisonColumns actual = (ComparisonColumns) decoded;
      assertEquals(actual.getComparableIndex(), expected.getComparableIndex());
      assertEquals(actual.getValues(), expected.getValues());
    } else {
      assertEquals(decoded, comparisonValue);
    }
  }

  @Test
  public void testNullComparisonValue() {
    assertNull(MetadataCodec.decodeComparisonValue(MetadataCodec.encodeUpsertValue(0, 0, null)));
  }

  @Test
  public void testDedupValueRoundTrip() {
    byte[] value = MetadataCodec.encodeDedupValue(Integer.MAX_VALUE, 1.7e12);
    assertEquals(value.length, MetadataCodec.DEDUP_VALUE_SIZE);
    assertEquals(MetadataCodec.decodeSegmentId(value), Integer.MAX_VALUE);
    assertEquals(MetadataCodec.decodeDedupTime(value), 1.7e12);
  }

  @Test
  public void testKeyEncoding() {
    String key = "txn-7f3a2c9e-4b1d-4e8a-9c6f-2d5b8e1a0c3f";
    PrimaryKey primaryKey = new PrimaryKey(new Object[]{key});
    assertEquals(MetadataCodec.encodeKey(HashUtils.hashPrimaryKey(primaryKey, HashFunction.NONE)),
        key.getBytes(StandardCharsets.UTF_8));
    byte[] murmur = MetadataCodec.encodeKey(HashUtils.hashPrimaryKey(primaryKey, HashFunction.MURMUR3));
    assertEquals(murmur.length, 16);
    assertEquals(murmur, HashUtils.hashMurmur3(primaryKey.asBytes()));
  }
}
