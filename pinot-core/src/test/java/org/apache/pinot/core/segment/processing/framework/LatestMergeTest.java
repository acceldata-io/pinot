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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.pinot.core.common.MinionConstants.MergeTask;
import org.apache.pinot.core.segment.processing.genericrow.GenericRowFileManager;
import org.apache.pinot.core.segment.processing.genericrow.GenericRowFileReader;
import org.apache.pinot.core.segment.processing.genericrow.GenericRowFileWriter;
import org.apache.pinot.core.segment.processing.reducer.Reducer;
import org.apache.pinot.core.segment.processing.reducer.ReducerFactory;
import org.apache.pinot.core.segment.processing.utils.SegmentProcessorUtils;
import org.apache.pinot.spi.config.table.TableConfig;
import org.apache.pinot.spi.config.table.TableType;
import org.apache.pinot.spi.data.FieldSpec;
import org.apache.pinot.spi.data.FieldSpec.DataType;
import org.apache.pinot.spi.data.Schema;
import org.apache.pinot.spi.data.readers.GenericRow;
import org.apache.pinot.spi.utils.builder.TableConfigBuilder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;


/**
 * Tests for LATEST merge. The reducer is not thread-safe; these tests run it on one thread.
 */
public class LatestMergeTest {
  private static final File TEMP_DIR = new File(FileUtils.getTempDirectory(), "LatestMergeTest");

  private File _inputDir;
  private File _outputDir;
  private Schema _schema;
  private TableConfig _tableConfig;

  @BeforeMethod
  public void setUp()
      throws IOException {
    FileUtils.deleteQuietly(TEMP_DIR);
    _inputDir = new File(TEMP_DIR, "input");
    _outputDir = new File(TEMP_DIR, "output");
    FileUtils.forceMkdir(_inputDir);
    FileUtils.forceMkdir(_outputDir);
    _schema = new Schema.SchemaBuilder().setSchemaName("testTable").addSingleValueDimension("pk", DataType.STRING)
        .addMetric("version", DataType.LONG).addSingleValueDimension("payload", DataType.STRING)
        .setPrimaryKeyColumns(Collections.singletonList("pk")).build();
    _tableConfig = new TableConfigBuilder(TableType.OFFLINE).setTableName("testTable").setNullHandlingEnabled(true)
        .build();
  }

  @AfterMethod
  public void tearDown() {
    FileUtils.deleteQuietly(TEMP_DIR);
  }

  @Test
  public void testKeepsNewestVersionAcrossSpillRuns()
      throws Exception {
    List<Object[]> rows = new ArrayList<>();
    rows.add(new Object[]{"a", 1L, "p1"});
    rows.add(new Object[]{"a", 5L, "p5"});
    rows.add(new Object[]{"b", 1L, "b1"});
    rows.add(new Object[]{"a", 3L, "p3"});
    rows.add(new Object[]{"b", 9L, "b9"});

    Map<String, String> taskConfig = baseTaskConfig();
    taskConfig.put(MergeTask.LATEST_MAX_ROWS_IN_MEMORY_KEY, "2");
    taskConfig.put(MergeTask.LATEST_MAX_MERGE_FAN_IN_KEY, "2");
    List<GenericRow> winners = reduce(rows, taskConfig);

    assertEquals(winners.size(), 2);
    assertEquals(winners.get(0).getValue("pk"), "a");
    assertEquals(winners.get(0).getValue("version"), 5L);
    assertEquals(winners.get(0).getValue("payload"), "p5");
    assertEquals(winners.get(1).getValue("pk"), "b");
    assertEquals(winners.get(1).getValue("version"), 9L);
    assertEquals(winners.get(1).getValue("payload"), "b9");
  }

  @Test
  public void testEqualVersionsKeepTheSameRow()
      throws Exception {
    List<Object[]> rows = new ArrayList<>();
    rows.add(new Object[]{"a", 4L, "first"});
    rows.add(new Object[]{"a", 4L, "second"});

    List<GenericRow> firstRun = reduce(rows, baseTaskConfig());
    List<GenericRow> secondRun = reduce(rows, baseTaskConfig());

    assertEquals(firstRun.size(), 1);
    assertEquals(firstRun.get(0).getValue("payload"), "second");
    assertEquals(secondRun.get(0).getValue("payload"), firstRun.get(0).getValue("payload"));
  }

  @Test
  public void testNullVersionLosesToARealVersion()
      throws Exception {
    Map<String, String> taskConfig = baseTaskConfig();
    List<Object[]> rows = new ArrayList<>();
    rows.add(new Object[]{"a", null, "old"});
    rows.add(new Object[]{"a", 2L, "new"});
    List<GenericRow> winners = reduce(rows, taskConfig);

    assertEquals(winners.size(), 1);
    assertEquals(winners.get(0).getValue("payload"), "new");
    assertEquals(winners.get(0).getValue("version"), 2L);
    assertFalse(winners.get(0).isNullValue("version"));
  }

  @Test
  public void testStatsReconcile()
      throws Exception {
    List<Object[]> rows = new ArrayList<>();
    rows.add(new Object[]{"a", 1L, "old"});
    rows.add(new Object[]{"a", 2L, "new"});
    rows.add(new Object[]{"b", 1L, "only"});
    SegmentProcessorConfig config = config(baseTaskConfig());
    reduce(rows, config);
    LatestMergeStats stats = config.getLatestMergeStats();
    assertEquals(stats.getRowsRead(), 3);
    assertEquals(stats.getRowsWritten(), 2);
    assertEquals(stats.getRowsRemoved(), 1);
  }

  @Test
  public void testMissingVersionColumnIsRejected() {
    Map<String, String> taskConfig = new HashMap<>();
    taskConfig.put(MergeTask.MERGE_TYPE_KEY, "latest");
    try {
      LatestMergeConfig.fromTaskConfig(_schema, taskConfig);
      fail();
    } catch (IllegalStateException e) {
      assertTrue(e.getMessage().contains(MergeTask.LATEST_VERSION_COLUMN_KEY));
    }
  }

  @Test
  public void testMultiValueVersionColumnIsRejected() {
    Schema schema = new Schema.SchemaBuilder().setSchemaName("testTable").addSingleValueDimension("pk", DataType.STRING)
        .addMultiValueDimension("version", DataType.LONG).setPrimaryKeyColumns(Collections.singletonList("pk"))
        .build();
    try {
      LatestMergeConfig.fromTaskConfig(schema, baseTaskConfig());
      fail();
    } catch (IllegalStateException e) {
      assertTrue(e.getMessage().contains("single-value"));
    }
  }

  @Test
  public void testEmptyPrimaryKeyIsRejected() {
    Schema schema = new Schema.SchemaBuilder().setSchemaName("testTable").addMetric("version", DataType.LONG).build();
    try {
      LatestMergeConfig.fromTaskConfig(schema, baseTaskConfig());
      fail();
    } catch (IllegalStateException e) {
      assertTrue(e.getMessage().contains("Primary key is empty"));
    }
  }

  private static Map<String, String> baseTaskConfig() {
    Map<String, String> taskConfig = new HashMap<>();
    taskConfig.put(MergeTask.MERGE_TYPE_KEY, "latest");
    taskConfig.put(MergeTask.LATEST_VERSION_COLUMN_KEY, "version");
    return taskConfig;
  }

  private List<GenericRow> reduce(List<Object[]> rows, Map<String, String> taskConfig)
      throws Exception {
    SegmentProcessorConfig config = config(taskConfig);
    return reduce(rows, config);
  }

  private List<GenericRow> reduce(List<Object[]> rows, SegmentProcessorConfig config)
      throws Exception {
    File inputDir = new File(_inputDir, "part-" + System.nanoTime());
    FileUtils.forceMkdir(inputDir);
    Pair<List<FieldSpec>, Integer> fieldSpecs =
        SegmentProcessorUtils.getFieldSpecs(_schema, MergeType.LATEST, null);
    assertEquals(fieldSpecs.getRight().intValue(), 0);
    GenericRowFileManager input =
        new GenericRowFileManager(inputDir, fieldSpecs.getLeft(), true, fieldSpecs.getRight());
    GenericRowFileWriter writer = input.getFileWriter();
    for (Object[] values : rows) {
      GenericRow row = new GenericRow();
      row.putValue("pk", values[0]);
      if (values[1] == null) {
        row.putDefaultNullValue("version", Long.MIN_VALUE);
      } else {
        row.putValue("version", values[1]);
      }
      row.putValue("payload", values[2]);
      writer.write(row);
    }
    input.closeFileWriter();

    Reducer reducer = ReducerFactory.getReducer("0", input, config, _outputDir);
    GenericRowFileManager reduced = reducer.reduce();
    GenericRowFileReader reader = reduced.getFileReader();
    List<GenericRow> winners = new ArrayList<>();
    GenericRow buffer = new GenericRow();
    for (int i = 0; i < reader.getNumRows(); i++) {
      buffer.clear();
      reader.read(i, buffer);
      winners.add(buffer.copy());
    }
    reduced.cleanUp();
    return winners;
  }

  private SegmentProcessorConfig config(Map<String, String> taskConfig) {
    return new SegmentProcessorConfig.Builder().setTableConfig(_tableConfig).setSchema(_schema)
        .setMergeType(MergeType.LATEST).setLatestMergeConfig(LatestMergeConfig.fromTaskConfig(_schema, taskConfig))
        .build();
  }
}
