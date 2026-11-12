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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.apache.commons.io.FileUtils;
import org.apache.pinot.common.metrics.ServerGauge;
import org.apache.pinot.common.metrics.ServerMetrics;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;


public class RocksDBMetadataMetricsTest {

  @SuppressWarnings("unchecked")
  @Test
  public void testPartitionGaugesReportStoreState()
      throws Exception {
    ServerMetrics serverMetrics = mock(ServerMetrics.class);
    Map<ServerGauge, Supplier<Long>> gauges = new HashMap<>();
    doAnswer(invocation -> {
      gauges.put(invocation.getArgument(2), invocation.getArgument(3));
      return null;
    }).when(serverMetrics).setOrUpdatePartitionGauge(anyString(), anyInt(), any(ServerGauge.class),
        any(Supplier.class));

    File dir = Files.createTempDirectory("rocksdb-metrics-test").toFile();
    RocksDBPartitionStore store = new RocksDBPartitionStore(new File(dir, "store"), List.of("default"),
        RocksDBMetadataStoreConfig.defaults());
    try {
      RocksDBMetadataMetrics.registerPartitionGauges(serverMetrics, "t_REALTIME", 3, store, () -> 7L);
      assertEquals(gauges.keySet(), Set.of(ServerGauge.ROCKSDB_METADATA_DISK_SIZE_BYTES,
          ServerGauge.ROCKSDB_METADATA_STORE_RETRIES, ServerGauge.ROCKSDB_METADATA_STORE_FAILURES,
          ServerGauge.ROCKSDB_METADATA_STALE_LOCATIONS));
      for (int i = 0; i < 1000; i++) {
        store.put(0, ("key-" + i).getBytes(StandardCharsets.UTF_8), new byte[16]);
      }
      assertTrue(gauges.get(ServerGauge.ROCKSDB_METADATA_DISK_SIZE_BYTES).get() > 0);
      assertEquals((long) gauges.get(ServerGauge.ROCKSDB_METADATA_STORE_RETRIES).get(), 0L);
      assertEquals((long) gauges.get(ServerGauge.ROCKSDB_METADATA_STORE_FAILURES).get(), 0L);
      assertEquals((long) gauges.get(ServerGauge.ROCKSDB_METADATA_STALE_LOCATIONS).get(), 7L);

      RocksDBMetadataMetrics.removePartitionGauges(serverMetrics, "t_REALTIME", 3);
      verify(serverMetrics).removePartitionGauge("t_REALTIME", 3, ServerGauge.ROCKSDB_METADATA_DISK_SIZE_BYTES);
      RocksDBMetadataMetrics.setInMemoryFallback(serverMetrics, "t_REALTIME", true);
      verify(serverMetrics).setValueOfTableGauge(eq("t_REALTIME"),
          eq(ServerGauge.ROCKSDB_METADATA_IN_MEMORY_FALLBACK), eq(1L));
    } finally {
      store.close();
      FileUtils.deleteQuietly(dir);
    }
    // Reading a gauge of a closed store returns 0 instead of touching the freed native handle
    assertEquals((long) gauges.get(ServerGauge.ROCKSDB_METADATA_DISK_SIZE_BYTES).get(), 0L);
  }
}
