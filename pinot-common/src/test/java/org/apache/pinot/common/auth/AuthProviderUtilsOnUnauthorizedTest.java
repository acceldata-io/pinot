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
package org.apache.pinot.common.auth;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.pinot.common.exception.HttpErrorStatusException;
import org.apache.pinot.spi.auth.AuthProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;


public class AuthProviderUtilsOnUnauthorizedTest {

  private static AuthProvider renewable(AtomicInteger renewals) {
    return new AuthProvider() {
      @Override
      public Map<String, Object> getRequestHeaders() {
        return Map.of();
      }

      @Override
      public String getTaskToken() {
        return null;
      }

      @Override
      public boolean onUnauthorized() {
        renewals.incrementAndGet();
        return true;
      }
    };
  }

  @Test
  public void testOnlyA401AnywhereInTheCauseChainRenews() {
    AtomicInteger renewals = new AtomicInteger();
    AuthProvider provider = renewable(renewals);
    assertTrue(AuthProviderUtils.onUnauthorized(provider, new HttpErrorStatusException("Unauthorized", 401)));
    assertTrue(AuthProviderUtils.onUnauthorized(provider,
        new IOException("upload failed", new HttpErrorStatusException("Unauthorized", 401))));
    assertFalse(AuthProviderUtils.onUnauthorized(provider, new HttpErrorStatusException("Forbidden", 403)));
    assertFalse(AuthProviderUtils.onUnauthorized(provider, new IOException("connection refused")));
    assertFalse(AuthProviderUtils.onUnauthorized(null, new HttpErrorStatusException("Unauthorized", 401)));
    assertEquals(renewals.get(), 2);
    // Static credentials cannot be renewed
    assertFalse(AuthProviderUtils.onUnauthorized(AuthProviderUtils.makeAuthProvider("Basic abc"),
        new HttpErrorStatusException("Unauthorized", 401)));
  }
}
