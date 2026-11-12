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
# Runbook: RocksDB upsert and dedup metadata

This runbook is for operators of servers whose upsert or dedup tables use `RocksDBTableUpsertMetadataManager` or
`RocksDBTableDedupMetadataManager`. Configuration, sizing and metrics are described in
[RocksDB-backed upsert and dedup metadata](rocksdb-metadata-store.md).

The store on each server is derived data. It is deleted and rebuilt from the segments every time a partition starts.
Deleting it, losing the disk, or restarting the server never loses data. It only costs rebuild time.

In the commands below, `$CONTROLLER` is the controller URL and `myTable_REALTIME` is the table name with type.

## Rollout checklist

1. Confirm the servers run a build that contains the RocksDB managers, including the controller (for config
   validation).
2. Size `dataDir` (local SSD, about 1.5 times the expected store size) and the native memory budget (block cache plus
   10 to 20%) on top of heap, direct memory and mmap.
3. Set the server-wide keys (`blockCacheSizeBytes`, `writeBufferManagerBytes`, `backgroundThreads`,
   `maintenanceThreads`) in the server config.
4. Enable on one table in staging by setting `metadataManagerClass`. The controller rejects invalid `rocksdb.*` keys
   at this step.
5. Restart one server and time the rebuild. Look for `Opened RocksDB metadata store in: ...` per partition in the
   server log.
6. Check that `ROCKSDB_METADATA_IN_MEMORY_FALLBACK` is 0, `ROCKSDB_METADATA_STORE_FAILURES` is 0, and
   `UPSERT_PRIMARY_KEYS_COUNT` or `DEDUP_PRIMARY_KEYS_COUNT` matches the in-memory value from before the switch.
7. Compare query results, for example `SELECT COUNT(*)` and a few primary-key lookups, against a replica that still
   uses the in-memory map.
8. Roll out to the remaining servers one at a time, waiting for each to be fully ONLINE.
9. Optionally turn on heap protection (`pinot.server.instance.ingestion.oom.protection.mode=UPSERT_DEDUP_ONLY`).

## Alert: ROCKSDB_METADATA_STORE_FAILURES increased

**Meaning.** A store operation failed after all retries. The consuming segment of that partition on that server went
to ERROR and stopped consuming. Other replicas keep serving and consuming. No row was skipped.

1. Find the server, table and partition from the gauge labels.
2. Search the server log for `RocksDB ... failed after N attempts in: <dir>`. The cause is the nested exception.
3. Fix the cause:
   - `No space left on device`: free disk space or grow the volume. See "Disk full" below.
   - `IO error`, read-only filesystem: the disk is failing. Replace it, or move the replica off the server.
   - `Corruption`: restart the server. The store is rebuilt from the segments.
   - Anything else: collect the log and report it.
4. Reset the ERROR segments of the table:

   ```bash
   curl -X POST "$CONTROLLER/segments/myTable_REALTIME/reset?errorSegmentsOnly=true"
   ```

   The consuming segment restarts from the last committed offset.
5. Check that the segment goes back to CONSUMING in the external view and that ingestion lag recovers.

## Alert: ROCKSDB_METADATA_IN_MEMORY_FALLBACK == 1

**Meaning.** The table is configured for RocksDB but uses the in-memory map on this server, so heap use grows with
the key count. Causes:

- The kill switch `rocksdb.enabled=false` is set at server or table level.
- `enableDeletedKeysCompactionConsistency` is set. New configs are rejected by the controller, but older tables may
  still have it.
- A store failed to open and `fallbackToInMemoryOnInitFailure=true` is set.

Steps:

1. Search the server log for `Using in-memory upsert metadata for table`, `Using in-memory dedup metadata for table`
   or `Failed to open RocksDB upsert metadata for table`. The line gives the reason.
2. Watch heap. If it is close to the limit, enable ingestion OOM protection for the table
   (`streamIngestionConfig.oomProtection=ENABLE`) while you fix the cause.
3. Fix the cause (remove the kill switch, fix the disk), then restart the server so the partitions reopen on
   RocksDB. A segment reload does not recreate the metadata manager.

## Alert: ROCKSDB_METADATA_STORE_RETRIES increasing steadily

**Meaning.** Operations fail and then succeed on retry. Ingestion slows by the backoff time. This is usually an
early sign of a disk problem.

1. Search the server log for `retrying in` and note the RocksDB error.
2. Check the disk: `df -h <dataDir>`, `iostat -x 5`, and `dmesg` for I/O errors.
3. If the disk is healthy and the errors are `Busy` or `TimedOut`, compaction is probably falling behind. Raise
   `backgroundThreads` or move `dataDir` to a faster disk.

## Disk full or nearly full on dataDir

1. Check the per-partition stores: `du -sh <dataDir>/*/*`. Compare with `ROCKSDB_METADATA_DISK_SIZE_BYTES`.
2. Directories of tables or partitions that no longer live on this server can be deleted while the server is
   stopped. Stores of partitions that are online must not be deleted while the server runs.
3. If the store grows faster than expected:
   - Check that `metadataTTL` or `deletedKeysTTL` is set as intended. TTL scans run on the maintenance pool. A scan
     limited by `ttlScanMaxKeysPerSecond` may not keep up with a high key churn rate, so raise or remove the limit.
   - Check that key cardinality matches expectations (`UPSERT_PRIMARY_KEYS_COUNT`).
4. Grow the volume, or move partitions to other servers by rebalancing the table.

## Server out of native memory or killed by the OOM killer

RocksDB memory is outside the Java heap, so the JVM won't report it as an `OutOfMemoryError`. The process is killed
by the kernel or container instead.

1. Compare the process RSS with `-Xmx` plus `-XX:MaxDirectMemorySize` plus `ROCKSDB_BLOCK_CACHE_CAPACITY_BYTES`.
2. Lower `blockCacheSizeBytes` or raise the container memory limit. `writeBufferManagerBytes` is charged to the
   block cache, so it doesn't add to the total.
3. Make sure only one value of the server-wide keys is in use. Search the log for `RocksDB environment already exists
   with block cache`, which means upsert and dedup asked for different sizes and the first one won.

## Java heap high or GC pauses on a RocksDB table

Heap is no longer proportional to the key count, but these still use heap:

- Preload buffers up to `preloadBatchKeys` keys per loading segment. Lower it if heap spikes during startup.
- The consuming (mutable) segments themselves.
- Query execution. Turn on the query OOM pause (`pinot.query.scheduler.accounting.oom.pre.query.kill.pause.duration.ms`
  and `pinot.query.scheduler.accounting.oom.panic.allow.pre.query.kill.pause`) so queries pause before a kill.

If heap is high and `ROCKSDB_METADATA_IN_MEMORY_FALLBACK` is 1, follow that alert first.

## Slow startup after a restart

Each partition rebuilds its store from its segments.

1. Check that `enableSnapshot` and `enablePreload` are set on upsert tables. Without them, segments are replayed
   through the normal upsert path.
2. Check disk throughput while loading. Preload writes sorted SST files for segments with at least
   `preloadSstMinKeys` keys, and is mostly bound by disk write speed.
3. Dedup tables don't use SST bulk load and rebuild more slowly per key.

## Ingestion lag growing, no errors

1. Check `ROCKSDB_BLOCK_CACHE_USAGE_BYTES` against capacity. If it stays at capacity, lookups go to disk. Raise
   `blockCacheSizeBytes`.
2. Check `REALTIME_INGESTION_OOM_PROTECTION_ACTIVE`. If it is 1, ingestion is paused for heap, not for RocksDB.
3. Check disk latency on `dataDir` with `iostat -x 5`.
4. Check that `asyncTtlScan` is `true`. With `false` the consuming thread runs the TTL scan and doesn't ingest while
   it runs.

## ROCKSDB_METADATA_STALE_LOCATIONS increasing

**Meaning.** A stored key pointed at a segment that was already released. The key is treated as absent, so results
stay correct, but this should not happen. Collect the server log and the table config, and report it.

## Emergency rollback to the in-memory map

Only do this if the table's keys fit on the heap. Otherwise the server will run out of heap.

1. Set the kill switch, at table level in `metadataManagerConfigs`:

   ```json
   "rocksdb.enabled": "false"
   ```

   Or for all tables on a server: `pinot.server.instance.upsert.rocksdb.enabled=false` (and the `dedup` equivalent).
2. Restart the servers one at a time. Partitions reopen with the in-memory map. A segment reload is not enough.
   `ROCKSDB_METADATA_IN_MEMORY_FALLBACK` becomes 1, which is expected during the rollback.
3. To roll back fully, remove `metadataManagerClass` from the table config and delete `<dataDir>` on the servers
   after they restart.
