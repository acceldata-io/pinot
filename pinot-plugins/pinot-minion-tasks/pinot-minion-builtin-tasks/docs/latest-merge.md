<!--

 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.

-->

# LATEST segment merge

`mergeType = latest` keeps one row per primary key when `MergeRollupTask` or `RealtimeToOfflineSegmentsTask` merges segments. The kept row is the one with the highest version-column value.

Use this when queries can wait until the merge to see the newest row. Tables that must show the newest row during ingestion should keep using upsert.

## Task settings

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `mergeType` | yes | | `latest` |
| `latest.versionColumn` | yes | | Column whose highest value wins. Null is older than any real value. |
| `latest.primaryKeyColumns` | no | schema primary key | Comma-separated columns that identify a record. |
| `latest.maxRowsInMemory` | no | `100000` | Rows sorted in memory before the rest spill to disk. |
| `latest.maxMergeFanIn` | no | `16` | Sorted runs opened at once while merging a spill. Must be at least 2. |

On `MergeRollupTask`, prefix the keys with the merge level, the same way as `mergeType`:

```
"daily.mergeType": "latest",
"daily.latest.versionColumn": "updatedAt",
"daily.latest.primaryKeyColumns": "userId"
```

Supported version and primary-key types are single-value `INT`, `LONG`, `FLOAT`, `DOUBLE`, `BOOLEAN`, `TIMESTAMP`, `STRING`, and `BIG_DECIMAL`. A multi-value column, a missing column, or an empty primary key fails the task when it is generated and again when it runs.

String versions are compared lexicographically. Use a numeric or timestamp column when the version is a number.

## Which row is kept

Rows are ordered by primary key, then by version ascending, then by the other single-value comparable columns in name order. The last row in each primary-key group is written. A null version sorts first, so a real version wins. When the version and those columns are equal, the later input row is kept, and a repeated run of the same input keeps the same row.

Each task logs `rowsRead`, `rowsWritten`, and `rowsRemoved`, with `rowsRemoved = rowsRead - rowsWritten`. The same counts are recorded on the Minion meters `latestMergeRowsRead`, `latestMergeRowsWritten`, and `latestMergeRowsRemoved`.

`CONCAT`, `ROLLUP`, and `DEDUP` are unchanged. The segment format and existing task keys are unchanged.

## Limits

- Versions are compared only among segments merged by the same task run.
- An update has to keep the original time-column value so every version lands in the same time bucket. A changed time column puts versions in different buckets, and one merge cannot see both.
- An update that arrives after a bucket was merged stays as a second copy until a later task includes both segments.
- Until a merge runs, queries see every version of the recent data.
- Each event has to carry the full row. A partial event would replace the previous row and drop the columns that were not sent.
- The in-scope table has to ingest every version. Ingestion-time dedup drops a later row before the Minion sees it.
- Memory is capped by `latest.maxRowsInMemory` and `latest.maxMergeFanIn`. Disk and runtime still grow with the number of input rows.
- `RealtimeToOfflineSegmentsTask` does not run on upsert tables.
