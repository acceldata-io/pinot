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
package org.apache.pinot.core.segment.processing.reducer;

import com.google.common.base.Preconditions;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.PriorityQueue;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.core.segment.processing.framework.LatestMergeConfig;
import org.apache.pinot.core.segment.processing.framework.LatestMergeStats;
import org.apache.pinot.core.segment.processing.genericrow.GenericRowFileManager;
import org.apache.pinot.core.segment.processing.genericrow.GenericRowFileReader;
import org.apache.pinot.core.segment.processing.genericrow.GenericRowFileWriter;
import org.apache.pinot.spi.data.FieldSpec;
import org.apache.pinot.spi.data.readers.GenericRow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Keeps the newest row for each primary key.
 * <p>
 * Rows are sorted on disk in chunks of {@link LatestMergeConfig#getMaxRowsInMemory()}. The sort order is primary key,
 * then version ascending, then the tie-break columns. A null version sorts first, so the last row of a key is the
 * newest. Memory stays at the configured chunk size plus one open run per
 * {@link LatestMergeConfig#getMaxMergeFanIn()} and does not grow with the number of keys.
 * <p>
 * Not thread-safe. One task thread owns an instance.
 */
public class LatestReducer implements Reducer {
  private static final Logger LOGGER = LoggerFactory.getLogger(LatestReducer.class);

  private final String _partitionId;
  private final GenericRowFileManager _fileManager;
  private final LatestMergeConfig _config;
  private final LatestMergeStats _stats;
  private final File _reducerOutputDir;
  private GenericRowFileManager _outputManager;

  public LatestReducer(String partitionId, GenericRowFileManager fileManager, LatestMergeConfig config,
      LatestMergeStats stats, File reducerOutputDir) {
    _partitionId = partitionId;
    _fileManager = fileManager;
    _config = config;
    _stats = stats;
    _reducerOutputDir = reducerOutputDir;
  }

  @Override
  public GenericRowFileManager reduce()
      throws Exception {
    File workDir = new File(_reducerOutputDir, _partitionId + "-latest-runs");
    try {
      return doReduce(workDir);
    } catch (Exception e) {
      if (_outputManager != null) {
        _outputManager.cleanUp();
      }
      throw e;
    } finally {
      FileUtils.deleteQuietly(workDir);
    }
  }

  private GenericRowFileManager doReduce(File workDir)
      throws Exception {
    Preconditions.checkState(_config != null, "LATEST merge config is required");
    Preconditions.checkState(_stats != null, "LATEST merge stats are required");
    LOGGER.info("Start LATEST reduce on partition: {}", _partitionId);
    long startTimeMs = System.currentTimeMillis();

    GenericRowFileReader fileReader = _fileManager.getFileReader();
    int numRows = fileReader.getNumRows();
    List<FieldSpec> fieldSpecs = _fileManager.getFieldSpecs();
    boolean includeNullFields = _fileManager.isIncludeNullFields();
    File partitionOutputDir = new File(_reducerOutputDir, _partitionId);
    FileUtils.forceMkdir(partitionOutputDir);

    long rowsWritten;
    if (numRows == 0) {
      _outputManager = createManager(partitionOutputDir, fieldSpecs, includeNullFields);
      _outputManager.getFileWriter();
      _outputManager.closeFileWriter();
      rowsWritten = 0;
    } else {
      FileUtils.forceMkdir(workDir);
      List<GenericRowFileManager> runs =
          writeSortedRuns(fileReader, numRows, fieldSpecs, includeNullFields, workDir);
      GenericRowFileManager sorted = mergeUntilOne(runs, fieldSpecs, includeNullFields, workDir);
      try {
        _outputManager = writeWinners(sorted, partitionOutputDir, fieldSpecs, includeNullFields);
        rowsWritten = _outputManager.getFileReader().getNumRows();
      } finally {
        sorted.cleanUp();
      }
    }

    _stats.add(numRows, rowsWritten);
    long rowsRemoved = numRows - rowsWritten;
    LOGGER.info(
        "Finish LATEST reduce on partition: {} in {}ms. rowsRead={}, rowsWritten={}, rowsRemoved={}",
        _partitionId, System.currentTimeMillis() - startTimeMs, numRows, rowsWritten, rowsRemoved);
    _fileManager.cleanUp();
    return _outputManager;
  }

  private List<GenericRowFileManager> writeSortedRuns(GenericRowFileReader fileReader, int numRows,
      List<FieldSpec> fieldSpecs, boolean includeNullFields, File workDir)
      throws IOException {
    List<GenericRowFileManager> runs = new ArrayList<>();
    List<SequencedRow> chunk = new ArrayList<>(Math.min(numRows, _config.getMaxRowsInMemory()));
    GenericRow buffer = new GenericRow();
    long sequence = 0;
    for (int rowId = 0; rowId < numRows; rowId++) {
      buffer.clear();
      fileReader.read(rowId, buffer);
      chunk.add(new SequencedRow(buffer.copy(), sequence++));
      if (chunk.size() == _config.getMaxRowsInMemory()) {
        runs.add(flushChunk(chunk, fieldSpecs, includeNullFields, new File(workDir, "run-" + runs.size())));
      }
    }
    if (!chunk.isEmpty()) {
      runs.add(flushChunk(chunk, fieldSpecs, includeNullFields, new File(workDir, "run-" + runs.size())));
    }
    LOGGER.info("LATEST partition {} spilled {} sorted runs for {} rows", _partitionId, runs.size(), numRows);
    return runs;
  }

  private GenericRowFileManager flushChunk(List<SequencedRow> chunk, List<FieldSpec> fieldSpecs,
      boolean includeNullFields, File runDir)
      throws IOException {
    chunk.sort(Comparator.comparing((SequencedRow row) -> row._row, _config::compare)
        .thenComparingLong(row -> row._sequence));
    GenericRowFileManager run = createManager(runDir, fieldSpecs, includeNullFields);
    GenericRowFileWriter writer = run.getFileWriter();
    for (SequencedRow sequencedRow : chunk) {
      writer.write(sequencedRow._row);
    }
    run.closeFileWriter();
    chunk.clear();
    return run;
  }

  private GenericRowFileManager mergeUntilOne(List<GenericRowFileManager> runs, List<FieldSpec> fieldSpecs,
      boolean includeNullFields, File workDir)
      throws IOException {
    List<GenericRowFileManager> current = runs;
    int generation = 0;
    while (current.size() > 1) {
      List<GenericRowFileManager> next = new ArrayList<>();
      int fanIn = _config.getMaxMergeFanIn();
      for (int start = 0; start < current.size(); start += fanIn) {
        int end = Math.min(start + fanIn, current.size());
        if (end - start == 1) {
          next.add(current.get(start));
          continue;
        }
        File mergedDir = new File(workDir, "merged-" + generation + "-" + next.size());
        List<GenericRowFileManager> group = current.subList(start, end);
        next.add(mergeGroup(group, fieldSpecs, includeNullFields, mergedDir));
        for (GenericRowFileManager source : group) {
          source.cleanUp();
        }
      }
      current = next;
      generation++;
    }
    return current.get(0);
  }

  private GenericRowFileManager mergeGroup(List<GenericRowFileManager> group, List<FieldSpec> fieldSpecs,
      boolean includeNullFields, File mergedDir)
      throws IOException {
    List<RunCursor> cursors = new ArrayList<>(group.size());
    for (int i = 0; i < group.size(); i++) {
      RunCursor cursor = new RunCursor(group.get(i).getFileReader(), i);
      if (cursor.advance()) {
        cursors.add(cursor);
      }
    }
    PriorityQueue<RunCursor> heap = new PriorityQueue<>(Math.max(1, cursors.size()), (left, right) -> {
      int compared = _config.compare(left._row, right._row);
      if (compared != 0) {
        return compared;
      }
      return Integer.compare(left._runSlot, right._runSlot);
    });
    heap.addAll(cursors);

    GenericRowFileManager merged = createManager(mergedDir, fieldSpecs, includeNullFields);
    GenericRowFileWriter writer = merged.getFileWriter();
    while (!heap.isEmpty()) {
      RunCursor cursor = heap.poll();
      writer.write(cursor._row);
      if (cursor.advance()) {
        heap.offer(cursor);
      }
    }
    merged.closeFileWriter();
    return merged;
  }

  private GenericRowFileManager writeWinners(GenericRowFileManager sorted, File partitionOutputDir,
      List<FieldSpec> fieldSpecs, boolean includeNullFields)
      throws IOException {
    GenericRowFileReader reader = sorted.getFileReader();
    int numRows = reader.getNumRows();
    GenericRowFileManager winners = createManager(partitionOutputDir, fieldSpecs, includeNullFields);
    GenericRowFileWriter writer = winners.getFileWriter();
    GenericRow buffer = new GenericRow();
    GenericRow winner = null;
    for (int rowId = 0; rowId < numRows; rowId++) {
      buffer.clear();
      reader.read(rowId, buffer);
      if (winner == null || _config.samePrimaryKey(winner, buffer)) {
        winner = buffer.copy();
      } else {
        writer.write(winner);
        winner = buffer.copy();
      }
    }
    if (winner != null) {
      writer.write(winner);
    }
    winners.closeFileWriter();
    return winners;
  }

  private static GenericRowFileManager createManager(File directory, List<FieldSpec> fieldSpecs,
      boolean includeNullFields)
      throws IOException {
    FileUtils.forceMkdir(directory);
    return new GenericRowFileManager(directory, fieldSpecs, includeNullFields, 0);
  }

  private static final class SequencedRow {
    private final GenericRow _row;
    private final long _sequence;

    private SequencedRow(GenericRow row, long sequence) {
      _row = row;
      _sequence = sequence;
    }
  }

  private static final class RunCursor {
    private final GenericRowFileReader _reader;
    private final int _runSlot;
    private final int _numRows;
    private int _nextRowId;
    private GenericRow _row;

    private RunCursor(GenericRowFileReader reader, int runSlot) {
      _reader = reader;
      _runSlot = runSlot;
      _numRows = reader.getNumRows();
    }

    private boolean advance() {
      if (_nextRowId >= _numRows) {
        _row = null;
        return false;
      }
      _row = new GenericRow();
      _reader.read(_nextRowId++, _row);
      return true;
    }
  }
}
