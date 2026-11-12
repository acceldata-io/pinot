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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.io.FileUtils;
import org.rocksdb.BlockBasedTableConfig;
import org.rocksdb.BloomFilter;
import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.ColumnFamilyOptions;
import org.rocksdb.CompactionStyle;
import org.rocksdb.CompressionType;
import org.rocksdb.DBOptions;
import org.rocksdb.EnvOptions;
import org.rocksdb.Filter;
import org.rocksdb.InfoLogLevel;
import org.rocksdb.IngestExternalFileOptions;
import org.rocksdb.Options;
import org.rocksdb.ReadOptions;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;
import org.rocksdb.SstFileWriter;
import org.rocksdb.WriteBatch;
import org.rocksdb.WriteOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * One RocksDB instance holding the metadata of one table partition, with one column family per logical map.
 *
 * <p>The store is a rebuildable cache of state that Pinot derives from segments on every start, so it is opened on an
 * empty directory, writes skip the write-ahead log, and the directory is deleted on {@link #close()}. Block cache,
 * memtable budget and background threads come from the shared {@link RocksDBEnvironment}.
 *
 * <p>Failed operations are retried with exponential backoff and then surface as
 * {@link RocksDBMetadataStoreException}. All methods are thread-safe; per-key read-modify-write atomicity is the
 * caller's job (see {@link StripedLocks}).
 */
@ThreadSafe
public class RocksDBPartitionStore implements AutoCloseable {
  private static final Logger LOGGER = LoggerFactory.getLogger(RocksDBPartitionStore.class);

  private final File _dir;
  private final RocksDBEnvironment _environment;
  private final RocksDBMetadataStoreConfig _config;
  private final DBOptions _dbOptions;
  private final ColumnFamilyOptions _cfOptions;
  private final Filter _bloomFilter;
  private final WriteOptions _writeOptions;
  private final ReadOptions _readOptions;
  private final RocksDB _db;
  private final List<ColumnFamilyHandle> _handles;
  private final AtomicLong _numRetries = new AtomicLong();
  private final AtomicLong _numFailures = new AtomicLong();
  private final AtomicLong _sstFileCounter = new AtomicLong();
  private volatile boolean _closed;

  /**
   * Opens a store in {@code dir} with the given column families. Anything left in {@code dir} by a previous run is
   * deleted first. The first column family is RocksDB's default one.
   */
  public RocksDBPartitionStore(File dir, List<String> columnFamilies, RocksDBMetadataStoreConfig config) {
    Preconditions.checkArgument(!columnFamilies.isEmpty(), "At least one column family is required");
    _dir = dir;
    _config = config;
    _environment = RocksDBEnvironment.acquire(config);
    DBOptions dbOptions = null;
    ColumnFamilyOptions cfOptions = null;
    Filter bloomFilter = null;
    WriteOptions writeOptions = null;
    ReadOptions readOptions = null;
    try {
      FileUtils.deleteDirectory(dir);
      FileUtils.forceMkdir(dir);
      dbOptions = new DBOptions()
          .setCreateIfMissing(true)
          .setCreateMissingColumnFamilies(true)
          .setWriteBufferManager(_environment.getWriteBufferManager())
          .setMaxBackgroundJobs(config.getBackgroundThreads())
          .setBytesPerSync(1L << 20)
          .setInfoLogLevel(InfoLogLevel.WARN_LEVEL)
          .setKeepLogFileNum(2)
          .setMaxLogFileSize(16L << 20);
      bloomFilter = new BloomFilter(config.getBloomBitsPerKey(), false);
      BlockBasedTableConfig tableConfig = new BlockBasedTableConfig()
          .setBlockCache(_environment.getBlockCache())
          .setFilterPolicy(bloomFilter)
          .setBlockSize(config.getBlockSizeBytes())
          .setCacheIndexAndFilterBlocks(true)
          .setCacheIndexAndFilterBlocksWithHighPriority(true)
          .setPinL0FilterAndIndexBlocksInCache(true)
          .setWholeKeyFiltering(true);
      cfOptions = new ColumnFamilyOptions()
          .setWriteBufferSize(config.getWriteBufferSizeBytes())
          .setMaxWriteBufferNumber(3)
          .setCompactionStyle(CompactionStyle.LEVEL)
          .setLevelCompactionDynamicLevelBytes(true)
          .setCompressionType(CompressionType.LZ4_COMPRESSION)
          .setBottommostCompressionType(CompressionType.ZSTD_COMPRESSION)
          .setMemtablePrefixBloomSizeRatio(0.1)
          .setMemtableWholeKeyFiltering(true)
          .setTableFormatConfig(tableConfig);
      List<ColumnFamilyDescriptor> descriptors = new ArrayList<>(columnFamilies.size());
      descriptors.add(new ColumnFamilyDescriptor(RocksDB.DEFAULT_COLUMN_FAMILY, cfOptions));
      for (int i = 1; i < columnFamilies.size(); i++) {
        descriptors.add(new ColumnFamilyDescriptor(columnFamilies.get(i).getBytes(StandardCharsets.UTF_8), cfOptions));
      }
      List<ColumnFamilyHandle> handles = new ArrayList<>(columnFamilies.size());
      writeOptions = new WriteOptions().setDisableWAL(true);
      readOptions = new ReadOptions();
      _db = RocksDB.open(dbOptions, dir.getAbsolutePath(), descriptors, handles);
      _handles = handles;
    } catch (RocksDBException | IOException | RuntimeException e) {
      closeQuietly(readOptions, writeOptions, cfOptions, bloomFilter, dbOptions);
      _environment.release();
      FileUtils.deleteQuietly(dir);
      throw new RocksDBMetadataStoreException("Failed to open RocksDB metadata store in: " + dir, e);
    }
    _dbOptions = dbOptions;
    _cfOptions = cfOptions;
    _bloomFilter = bloomFilter;
    _writeOptions = writeOptions;
    _readOptions = readOptions;
    LOGGER.info("Opened RocksDB metadata store in: {} with column families: {}", dir, columnFamilies);
  }

  @FunctionalInterface
  interface StoreOperation<T> {
    T run()
        throws RocksDBException;
  }

  @VisibleForTesting
  <T> T withRetry(String operation, StoreOperation<T> storeOperation) {
    long backoffMs = _config.getRetryBackoffMs();
    int maxRetries = _config.getMaxRetries();
    for (int attempt = 0; ; attempt++) {
      Preconditions.checkState(!_closed, "RocksDB metadata store in: %s is closed", _dir);
      try {
        return storeOperation.run();
      } catch (RocksDBException e) {
        if (attempt >= maxRetries) {
          _numFailures.incrementAndGet();
          throw new RocksDBMetadataStoreException(
              String.format("RocksDB %s failed after %d attempts in: %s", operation, attempt + 1, _dir), e);
        }
        _numRetries.incrementAndGet();
        LOGGER.warn("RocksDB {} failed in: {} (attempt {}), retrying in {}ms", operation, _dir, attempt + 1,
            backoffMs, e);
        try {
          Thread.sleep(backoffMs);
        } catch (InterruptedException ie) {
          Thread.currentThread().interrupt();
          throw new RocksDBMetadataStoreException("Interrupted while retrying RocksDB " + operation, e);
        }
        backoffMs = Math.max(1, backoffMs * 2);
      }
    }
  }

  @Nullable
  public byte[] get(int columnFamily, byte[] key) {
    ColumnFamilyHandle handle = _handles.get(columnFamily);
    return withRetry("get", () -> _db.get(handle, _readOptions, key));
  }

  public void put(int columnFamily, byte[] key, byte[] value) {
    ColumnFamilyHandle handle = _handles.get(columnFamily);
    withRetry("put", () -> {
      _db.put(handle, _writeOptions, key, value);
      return null;
    });
  }

  public void delete(int columnFamily, byte[] key) {
    ColumnFamilyHandle handle = _handles.get(columnFamily);
    withRetry("delete", () -> {
      _db.delete(handle, _writeOptions, key);
      return null;
    });
  }

  /// Applies a batch built by {@link #newWriteBatch()}. The batch is closed by the caller.
  public void write(WriteBatch batch) {
    withRetry("write batch", () -> {
      _db.write(_writeOptions, batch);
      return null;
    });
  }

  public WriteBatch newWriteBatch() {
    return new WriteBatch();
  }

  public ColumnFamilyHandle getHandle(int columnFamily) {
    return _handles.get(columnFamily);
  }

  /// Returns an iterator over a column family. The caller must close it, and must not use it after {@link #close()}.
  public RocksIterator newIterator(int columnFamily) {
    Preconditions.checkState(!_closed, "RocksDB metadata store in: %s is closed", _dir);
    return _db.newIterator(_handles.get(columnFamily));
  }

  /**
   * Writes {@code keys} and {@code values} into a new SST file and ingests it into the column family. Keys must be
   * strictly increasing in unsigned byte order. Used to load large batches during preload without memtable writes.
   */
  public void ingestSorted(int columnFamily, List<byte[]> keys, List<byte[]> values) {
    Preconditions.checkArgument(keys.size() == values.size(), "Keys and values must have the same size");
    if (keys.isEmpty()) {
      return;
    }
    File sstFile = new File(_dir, "ingest_" + _sstFileCounter.incrementAndGet() + ".sst");
    try {
      withRetry("SST ingest", () -> {
        try (EnvOptions envOptions = new EnvOptions();
            Options options = new Options(_dbOptions, _cfOptions);
            SstFileWriter writer = new SstFileWriter(envOptions, options)) {
          writer.open(sstFile.getAbsolutePath());
          for (int i = 0; i < keys.size(); i++) {
            writer.put(keys.get(i), values.get(i));
          }
          writer.finish();
        }
        try (IngestExternalFileOptions ingestOptions = new IngestExternalFileOptions().setMoveFiles(true)) {
          _db.ingestExternalFile(_handles.get(columnFamily), List.of(sstFile.getAbsolutePath()), ingestOptions);
        }
        return null;
      });
    } finally {
      FileUtils.deleteQuietly(sstFile);
    }
  }

  /// Returns a RocksDB integer property such as {@code rocksdb.total-sst-files-size}, or 0 if it is unavailable.
  /// Synchronized with {@link #close()}, so metrics threads never read a closed native handle.
  public synchronized long getLongProperty(int columnFamily, String property) {
    if (_closed) {
      return 0;
    }
    try {
      return _db.getLongProperty(_handles.get(columnFamily), property);
    } catch (RocksDBException e) {
      return 0;
    }
  }

  public long getNumRetries() {
    return _numRetries.get();
  }

  public long getNumFailures() {
    return _numFailures.get();
  }

  public File getDir() {
    return _dir;
  }

  public RocksDBEnvironment getEnvironment() {
    return _environment;
  }

  public boolean isClosed() {
    return _closed;
  }

  /// Closes the store, frees its native resources and deletes its directory. Idempotent.
  @Override
  public synchronized void close() {
    if (_closed) {
      return;
    }
    _closed = true;
    for (ColumnFamilyHandle handle : _handles) {
      handle.close();
    }
    _db.close();
    closeQuietly(_readOptions, _writeOptions, _cfOptions, _bloomFilter, _dbOptions);
    _environment.release();
    FileUtils.deleteQuietly(_dir);
    LOGGER.info("Closed RocksDB metadata store in: {}", _dir);
  }

  /// SST files plus memtables of all column families.
  public synchronized long getDiskSizeBytes() {
    long sizeBytes = 0;
    for (int i = 0; i < _handles.size(); i++) {
      sizeBytes += getLongProperty(i, "rocksdb.total-sst-files-size");
      sizeBytes += getLongProperty(i, "rocksdb.cur-size-all-mem-tables");
    }
    return sizeBytes;
  }

  private static void closeQuietly(AutoCloseable... closeables) {
    for (AutoCloseable closeable : closeables) {
      if (closeable != null) {
        try {
          closeable.close();
        } catch (Exception e) {
          LOGGER.warn("Failed to close RocksDB resource: {}", closeable, e);
        }
      }
    }
  }
}
