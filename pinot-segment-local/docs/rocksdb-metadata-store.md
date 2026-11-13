<!--

 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements. See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership. The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied. See the License for the
 specific language governing permissions and limitations
 under the License.

-->
# RocksDB-backed upsert and dedup metadata

By default Pinot keeps upsert and dedup metadata (primary key to record location, or primary key to dedup time) in
an on-heap `ConcurrentHashMap` per partition. Heap use grows with the number of live primary keys, so tables with
hundreds of millions or billions of keys per server run out of heap or spend most of their time in GC.

The RocksDB metadata managers keep the same metadata in a local RocksDB store per partition. The heap then holds
only a small cache, and the key count is limited by local disk. Query results, upsert/dedup semantics, TTL, partial
upsert and preload behave the same as with the in-memory managers. Parity tests compare the two implementations
operation by operation.

Related on-call guide: [RocksDB metadata runbook](rocksdb-metadata-store-runbook.md).

## When to use it

Use it when the number of live primary keys per server is too large for the heap. A rough guide: the in-memory map
costs about 100 to 200 bytes of heap per key (key bytes, location object, map entry). At 500M keys per server that
is 50 to 100 GB of heap.

Keep the in-memory managers for small tables. They are faster per lookup, and RocksDB adds disk I/O and native memory
that small tables don't need.

## Supported features

| Feature | RocksDB upsert | RocksDB dedup |
|---|---|---|
| Full and partial upsert, comparison columns, delete record column | Yes | n/a |
| `metadataTTL` and `deletedKeysTTL` | Yes, scanned off the consuming thread | `metadataTTL` yes |
| Snapshot and preload (`enableSnapshot`, `enablePreload`) | Yes, with SST bulk load | Yes, one key at a time |
| `dropOutOfOrderRecord`, `outOfOrderRecordColumn` | Yes | n/a |
| `enableDeletedKeysCompactionConsistency` | No, rejected at table create | n/a |

## How it works

- One RocksDB store per table partition on each server, in `<dataDir>/<tableNameWithType>/upsert_<partition>` or
  `.../dedup_<partition>`.
- The store is derived data. It is deleted and rebuilt from the segments every time the partition starts, so it has
  no write-ahead log and needs no backup. Losing the disk loses nothing.
- All stores on a server share one LRU block cache, one write buffer manager (memtables are charged to the block
  cache), one flush and compaction pool, and one maintenance pool for TTL scans.
- Segments are stored as small integer ids with reference counts, so keys don't hold segment objects and released
  segments can be garbage collected.
- TTL scans run on the maintenance pool and are rate limited. Ingestion keeps going while a scan runs.

## Enabling it

### For every upsert or dedup table on a server

Add to the server config and restart the server:

```properties
pinot.server.instance.upsert.default.metadata.manager.class=org.apache.pinot.segment.local.upsert.RocksDBTableUpsertMetadataManager
pinot.server.instance.dedup.default.metadata.manager.class=org.apache.pinot.segment.local.dedup.RocksDBTableDedupMetadataManager
```

### For one table

Set `metadataManagerClass` in the table config, then restart the servers hosting the table one at a time. The
metadata manager is created when the table starts on a server, so a segment reload doesn't switch it:

```json
"upsertConfig": {
  "mode": "FULL",
  "metadataManagerClass": "org.apache.pinot.segment.local.upsert.RocksDBTableUpsertMetadataManager",
  "metadataManagerConfigs": {
    "rocksdb.ttlScanMaxKeysPerSecond": "2000000"
  }
}
```

The dedup equivalent uses `dedupConfig.metadataManagerClass` set to
`org.apache.pinot.segment.local.dedup.RocksDBTableDedupMetadataManager`.

## Configuration

Settings are read at two levels:

- **Server level:** `pinot.server.instance.upsert.rocksdb.<key>` for upsert tables and
  `pinot.server.instance.dedup.rocksdb.<key>` for dedup tables.
- **Table level:** `upsertConfig.metadataManagerConfigs` or `dedupConfig.metadataManagerConfigs`, with the key
  prefixed by `rocksdb.`, for example `"rocksdb.maxRetries": "5"`. Table values override server values.

Keys are case-insensitive and ignore `-` and `_`, so `preloadBatchKeys` and `preload_batch_keys` are the same key.

### Server-wide keys (server config only)

These size resources shared by every store on the server. The controller rejects them in a table config. If upsert
and dedup tables ask for different values, the first table to open a store wins and later ones log a warning.

| Key | Default | Meaning |
|---|---|---|
| `blockCacheSizeBytes` | 1073741824 (1 GiB) | Shared LRU block cache. Memtables are charged to it too. |
| `writeBufferManagerBytes` | 268435456 (256 MiB) | Total memtable budget across all stores. |
| `backgroundThreads` | 4 | RocksDB flush and compaction threads. |
| `maintenanceThreads` | 2 | Threads that run TTL scans for all partitions. |

### Per-table keys

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Kill switch. `false` makes the RocksDB manager use the in-memory map. |
| `dataDir` | `<server data dir>/rocksdb_metadata` | Root directory of the stores. Must be an absolute path. |
| `writeBufferSizeBytes` | 67108864 (64 MiB) | Size of one memtable. Minimum 1 MiB. |
| `bloomBitsPerKey` | 10 | Bloom filter bits per key. 10 gives about 1% false positives. |
| `blockSizeBytes` | 4096 | Data block size. Minimum 1 KiB. Small blocks favour point lookups. |
| `maxRetries` | 3 | Retries of a failed store operation before it fails. |
| `retryBackoffMs` | 100 | Initial backoff between retries; doubles on every retry. |
| `ttlScanMaxKeysPerSecond` | 0 (unlimited) | Rate limit of the TTL scan. |
| `asyncTtlScan` | `true` | Run TTL scans on the maintenance pool instead of the consuming thread. |
| `preloadSstMinKeys` | 100000 | Segments with at least this many valid keys are preloaded through a sorted SST file. 0 disables it. |
| `preloadBatchKeys` | 500000 | Most keys of one segment buffered on the heap during preload. |
| `snapshotSegmentLockWaitMs` | 10000 | How long a validDocIds snapshot waits for the lock of a segment that is still being committed. 0 skips the segment at once, as the in-memory managers do; replacing a segment takes longer on RocksDB, so the just-committed segment would then be skipped at almost every commit and no segment would get its first snapshot. |
| `fallbackToInMemoryOnInitFailure` | `false` | Use the in-memory map if a store can't be opened. |

### Validation

The controller validates `rocksdb.*` table keys when a table is created or updated and rejects:

- unknown keys, which are usually typos,
- server-wide keys,
- booleans other than `true` or `false`,
- a relative `dataDir`,
- numbers that don't parse or are below the minimum,
- `enableDeletedKeysCompactionConsistency` combined with the RocksDB upsert manager.

Server-level keys are not seen by the controller. They are parsed when a table's metadata manager is created on the
server, and a bad value fails that table on that server, so check the server log after changing them.

## Sizing

**Disk.** Plan for about 1.5 times the raw size of the stored keys and values, which leaves room for compaction. Each
entry holds the primary key bytes plus about 16 to 24 bytes (segment id, doc id, comparison value) and is compressed
with LZ4 and ZSTD. Watch `ROCKSDB_METADATA_DISK_SIZE_BYTES` after enabling and size from real numbers. Put `dataDir`
on local SSD or NVMe. Network disks add latency to every ingested row.

**Native memory.** RocksDB memory is off-heap, outside `-Xmx`. Budget about `blockCacheSizeBytes` plus 10 to 20% for
the server. The container or host memory limit must cover heap + direct memory + mmap'd segments + this budget.

**Block cache.** Index and filter blocks are cached with high priority and should stay resident. They need about
`bloomBitsPerKey / 8` bytes per key, so 1B keys with 10 bits per key need about 1.25 GB for filters alone. Size the
cache so filters fit with room left for data blocks. If `ROCKSDB_BLOCK_CACHE_USAGE_BYTES` stays at capacity and
ingestion slows, raise the cache.

**Heap.** Heap is no longer proportional to the key count. Preload temporarily buffers up to `preloadBatchKeys` keys
per segment being loaded.

## Heap protection

Two server-side heap guards are available on this branch. They are independent of RocksDB and useful for any upsert
or dedup table. Both are off by default.

- **Ingestion OOM protection.** Consumers pause fetching while heap use is at or above a threshold and resume below a
  lower one. Server config:
  `pinot.server.instance.ingestion.oom.protection.mode` (`DISABLE`, `ENABLE` or `UPSERT_DEDUP_ONLY`),
  `...heapUsageThrottleThreshold` (default 0.95), `...heapUsageRecoveryThreshold` (default 0.90),
  `...checkIntervalMs` (default 1000) and `...gcIntervalMs` (default 30000). Tables can override the mode with
  `streamIngestionConfig.oomProtection` (`ENABLE`, `DISABLE` or `DEFAULT`). Gauge:
  `REALTIME_INGESTION_OOM_PROTECTION_ACTIVE`.
- **Query OOM pause.** When heap first reaches the critical level, query threads pause and a GC is requested before
  the most expensive query is killed. Cluster configs:
  `pinot.query.scheduler.accounting.oom.pre.query.kill.pause.duration.ms` (default -1, off) and
  `pinot.query.scheduler.accounting.oom.panic.allow.pre.query.kill.pause` (default `false`).

## Metrics

| Gauge | Scope | Meaning |
|---|---|---|
| `ROCKSDB_METADATA_DISK_SIZE_BYTES` | table, partition | SST files plus memtables of the partition's store |
| `ROCKSDB_METADATA_STORE_RETRIES` | table, partition | Cumulative retried store operations |
| `ROCKSDB_METADATA_STORE_FAILURES` | table, partition | Cumulative operations that failed after all retries |
| `ROCKSDB_METADATA_STALE_LOCATIONS` | table, partition | Cumulative keys found pointing at a released segment |
| `ROCKSDB_METADATA_IN_MEMORY_FALLBACK` | table | 1 if the table is configured for RocksDB but uses the in-memory map |
| `ROCKSDB_BLOCK_CACHE_USAGE_BYTES` | server | Bytes in the shared block cache |
| `ROCKSDB_BLOCK_CACHE_PINNED_USAGE_BYTES` | server | Bytes pinned in the shared block cache |
| `ROCKSDB_BLOCK_CACHE_CAPACITY_BYTES` | server | Capacity of the shared block cache |

Partition gauges are removed when the partition closes. The existing upsert and dedup gauges, such as
`UPSERT_PRIMARY_KEYS_COUNT` and `DEDUP_PRIMARY_KEYS_COUNT`, keep working.

Suggested alerts:

- `ROCKSDB_METADATA_STORE_FAILURES` increases: page. A consuming segment has gone to ERROR on that replica.
- `ROCKSDB_METADATA_IN_MEMORY_FALLBACK == 1`: page. The table is on the heap and may run out of it.
- `ROCKSDB_METADATA_STORE_RETRIES` increasing steadily: warn. The disk is failing or full.
- Free space on the `dataDir` filesystem below 20%: warn.
- `ROCKSDB_METADATA_STALE_LOCATIONS` increasing steadily: warn. This points to a bug; report it with logs.

## Failure handling

- **Store errors** (any `RocksDBException`, for example a busy, timed-out or I/O-failed operation) are retried
  `maxRetries` times with exponential backoff and counted in `ROCKSDB_METADATA_STORE_RETRIES`. Each retry is logged
  at WARN as `RocksDB <operation> failed in: <dir> (attempt N), retrying in Xms`.
- **Persistent errors during ingestion** are not swallowed. The row is not silently dropped: the consuming segment on
  that replica goes to ERROR and stops consuming, and the failure is counted in `ROCKSDB_METADATA_STORE_FAILURES`.
  Other replicas and partitions keep consuming. Fix the cause, then reset the segment (see the runbook).
- **A store that fails to open** fails the partition on that server. With `fallbackToInMemoryOnInitFailure=true` the
  table uses the in-memory map instead and sets `ROCKSDB_METADATA_IN_MEMORY_FALLBACK=1`. It is off by default because
  a table sized for RocksDB can exhaust the heap.
- **The kill switch** `enabled=false` (server or table level) switches to the in-memory map on the next start of the
  table on that server. Only use it for tables whose keys fit on the heap.

## Restart and preload

On start, each partition deletes its old store and rebuilds it from the segments on disk. With `enableSnapshot` and
`enablePreload`, sealed segments are loaded through the preload path. Their valid keys are written with batched
inserts, and segments with at least `preloadSstMinKeys` keys are written as sorted SST files and ingested directly,
skipping memtables and compaction. Without preload, segments are replayed through the normal upsert path, which is
slower for large tables.

Expect startup to be bound by disk throughput. Measure it on a staging server before rolling out.

## Limitations

- `enableDeletedKeysCompactionConsistency` is not supported.
- Dedup preload writes one key at a time; there is no SST bulk load for dedup.
- The store is local to a server. Moving a partition to another server rebuilds it there from the segments.
