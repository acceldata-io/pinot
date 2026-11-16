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
package org.apache.pinot.sql.parsers.rewriter;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.pinot.spi.utils.CommonConstants;
import org.apache.pinot.sql.parsers.CalciteSqlParser;


public class RlsUtils {

  private RlsUtils() {
  }

  public static String buildRlsFilterKey(String tableName) {
    return String.format("%s-%s", CommonConstants.RLS_FILTERS, tableName);
  }

  public static Map<String, String> extractRlsFilters(Map<String, String> requestMetadata) {
    return requestMetadata.entrySet().stream()
        .filter(e -> e.getKey().startsWith(CommonConstants.RLS_FILTERS))
        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }

  public static String getRlsFilterForTable(Map<String, String> queryOptions, String tableName) {
    return queryOptions.get(buildRlsFilterKey(tableName));
  }

  /**
   * Combines the row filters of a table into one predicate that requires all of them, after checking that each
   * parses. A filter that does not parse must deny the query: running it without the filter would return rows the
   * principal may not see.
   *
   * @throws InvalidRowFilterException if a filter does not parse
   */
  public static String combineRowFilters(String tableName, List<String> rowFilters) {
    for (String rowFilter : rowFilters) {
      try {
        CalciteSqlParser.compileToExpression(rowFilter);
      } catch (RuntimeException e) {
        throw new InvalidRowFilterException(tableName, rowFilter, e);
      }
    }
    return rowFilters.stream().map(filter -> "( " + filter + " )").collect(Collectors.joining(" AND "));
  }

  /**
   * A row filter that does not parse. The message names the table only: the filter is part of the access policy and
   * is not shown to the client; {@link #getRowFilter()} gives it for the server log.
   */
  public static class InvalidRowFilterException extends IllegalArgumentException {
    private final String _rowFilter;

    public InvalidRowFilterException(String tableName, String rowFilter, Throwable cause) {
      super("A row filter of table " + tableName + " does not parse", cause);
      _rowFilter = rowFilter;
    }

    public String getRowFilter() {
      return _rowFilter;
    }
  }
}
