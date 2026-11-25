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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;


/**
 * Describes the segments a RocksDB checkpoint covers, so a restart can reopen the checkpoint instead of reading every
 * key back out of those segments. The checkpoint is usable only when the segments now on the server are exactly this
 * set, with the same CRC, and the table still uses the same key schema. Anything else rebuilds the store.
 *
 * <p>Immutable. The file form is plain text, one fact per line.
 */
@Immutable
public final class RocksDBRecoveryManifest {
  public static final String FILE_NAME = "manifest";
  private static final String VERSION = "v1";

  private final String _fingerprint;
  private final double _watermark;
  private final long _numPrimaryKeys;
  private final Map<String, Segment> _segments;

  /// One sealed segment covered by the checkpoint.
  @Immutable
  public static final class Segment {
    private final long _crc;
    private final int _id;
    private final long _refCount;

    public Segment(long crc, int id, long refCount) {
      _crc = crc;
      _id = id;
      _refCount = refCount;
    }

    public long getCrc() {
      return _crc;
    }

    /// Segment id stored in the checkpoint values, or -1 when the segment has no keys.
    public int getId() {
      return _id;
    }

    public long getRefCount() {
      return _refCount;
    }
  }

  public RocksDBRecoveryManifest(String fingerprint, double watermark, long numPrimaryKeys,
      Map<String, Segment> segments) {
    _fingerprint = fingerprint;
    _watermark = watermark;
    _numPrimaryKeys = numPrimaryKeys;
    _segments = Collections.unmodifiableMap(new LinkedHashMap<>(segments));
  }

  public String getFingerprint() {
    return _fingerprint;
  }

  public double getWatermark() {
    return _watermark;
  }

  public long getNumPrimaryKeys() {
    return _numPrimaryKeys;
  }

  public Map<String, Segment> getSegments() {
    return _segments;
  }

  /**
   * @param onlineSegmentCrcs sealed segments the server would otherwise rebuild from, keyed by segment name
   * @return why the checkpoint cannot be used, or {@code null} when it matches
   */
  @Nullable
  public String mismatch(String fingerprint, Map<String, Long> onlineSegmentCrcs) {
    if (!_fingerprint.equals(fingerprint)) {
      return "table key config changed";
    }
    if (_segments.size() != onlineSegmentCrcs.size()) {
      return "segment count " + _segments.size() + " in the checkpoint, " + onlineSegmentCrcs.size() + " on the server";
    }
    for (Map.Entry<String, Long> online : onlineSegmentCrcs.entrySet()) {
      Segment segment = _segments.get(online.getKey());
      if (segment == null) {
        return "segment " + online.getKey() + " is not in the checkpoint";
      }
      if (segment.getCrc() != online.getValue()) {
        return "segment " + online.getKey() + " changed";
      }
    }
    return null;
  }

  public void write(File file)
      throws IOException {
    StringBuilder text = new StringBuilder();
    text.append(VERSION).append('\n');
    text.append("fingerprint\t").append(_fingerprint).append('\n');
    text.append("watermark\t").append(_watermark).append('\n');
    text.append("keys\t").append(_numPrimaryKeys).append('\n');
    for (Map.Entry<String, Segment> entry : _segments.entrySet()) {
      Segment segment = entry.getValue();
      text.append("segment\t").append(segment.getCrc()).append('\t').append(segment.getId()).append('\t')
          .append(segment.getRefCount()).append('\t').append(entry.getKey()).append('\n');
    }
    Files.writeString(file.toPath(), text, StandardCharsets.UTF_8);
  }

  /// @return the manifest, or {@code null} when the file is missing or not understandable
  @Nullable
  public static RocksDBRecoveryManifest read(File file) {
    if (!file.isFile()) {
      return null;
    }
    try {
      String fingerprint = null;
      double watermark = Double.NEGATIVE_INFINITY;
      long numPrimaryKeys = -1;
      Map<String, Segment> segments = new LinkedHashMap<>();
      boolean header = true;
      for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
        if (line.isEmpty()) {
          continue;
        }
        if (header) {
          if (!VERSION.equals(line)) {
            return null;
          }
          header = false;
          continue;
        }
        String[] parts = line.split("\t", -1);
        switch (parts[0]) {
          case "fingerprint":
            fingerprint = parts[1];
            break;
          case "watermark":
            watermark = Double.parseDouble(parts[1]);
            break;
          case "keys":
            numPrimaryKeys = Long.parseLong(parts[1]);
            break;
          case "segment":
            segments.put(parts[4], new Segment(Long.parseLong(parts[1]), Integer.parseInt(parts[2]),
                Long.parseLong(parts[3])));
            break;
          default:
            return null;
        }
      }
      if (fingerprint == null || numPrimaryKeys < 0) {
        return null;
      }
      return new RocksDBRecoveryManifest(fingerprint, watermark, numPrimaryKeys, segments);
    } catch (Exception e) {
      return null;
    }
  }
}
