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
/**
 * RocksDB-backed storage for upsert and dedup metadata, used by
 * {@link org.apache.pinot.segment.local.upsert.RocksDBTableUpsertMetadataManager} and
 * {@link org.apache.pinot.segment.local.dedup.RocksDBTableDedupMetadataManager}.
 *
 * <ul>
 *   <li>{@link org.apache.pinot.segment.local.rocksdb.RocksDBEnvironment}: block cache, write buffer manager and
 *   thread pools shared by all stores of a server.</li>
 *   <li>{@link org.apache.pinot.segment.local.rocksdb.RocksDBPartitionStore}: one RocksDB instance per partition,
 *   with retries and failure accounting.</li>
 *   <li>{@link org.apache.pinot.segment.local.rocksdb.PrimaryKeyLocationStore} and
 *   {@link org.apache.pinot.segment.local.rocksdb.DedupKeyStore}: upsert and dedup views over a partition store.</li>
 *   <li>{@link org.apache.pinot.segment.local.rocksdb.SegmentRegistry}: maps segments to reference-counted ids.</li>
 *   <li>{@link org.apache.pinot.segment.local.rocksdb.RocksDBMetadataStoreConfig}: server and table settings.</li>
 * </ul>
 *
 * <p>Stores are derived data: each is deleted and rebuilt from the segments when its partition starts. Configuration,
 * sizing, metrics and the operator runbook are in {@code pinot-segment-local/docs/rocksdb-metadata-store.md} and
 * {@code pinot-segment-local/docs/rocksdb-metadata-store-runbook.md}.
 */
package org.apache.pinot.segment.local.rocksdb;
