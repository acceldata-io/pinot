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
package org.apache.pinot.server.api.resources;

import io.netty.channel.ChannelHandlerContext;
import java.util.function.Supplier;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedHashMap;
import org.apache.pinot.server.access.AccessControl;
import org.apache.pinot.server.access.AccessControlFactory;
import org.apache.pinot.spi.auth.server.RequesterIdentity;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.expectThrows;


/// Data access checks of the server REST API keep the access control's own answer: 401 (with its challenge) for a
/// missing or rejected credential and 403 for a denied table; only unexpected failures become 500.
public class ServerResourceUtilsTest {

  private static AccessControlFactory factory(Supplier<Boolean> dataAccess) {
    AccessControl accessControl = new AccessControl() {
      @Override
      public boolean isAuthorizedChannel(ChannelHandlerContext channelHandlerContext) {
        return true;
      }

      @Override
      public boolean hasDataAccess(RequesterIdentity requesterIdentity, String tableName) {
        return dataAccess.get();
      }
    };
    return () -> accessControl;
  }

  private static HttpHeaders headers() {
    HttpHeaders headers = mock(HttpHeaders.class);
    when(headers.getRequestHeaders()).thenReturn(new MultivaluedHashMap<>());
    return headers;
  }

  @Test
  public void testValidateDataAccess() {
    ServerResourceUtils.validateDataAccess(factory(() -> true), "orders_OFFLINE", headers());

    NotAuthorizedException unauthenticated = expectThrows(NotAuthorizedException.class,
        () -> ServerResourceUtils.validateDataAccess(factory(() -> {
          throw new NotAuthorizedException("Missing credential", "Basic realm=\"pinot\"");
        }), "orders_OFFLINE", headers()));
    assertEquals(unauthenticated.getChallenges().get(0), "Basic realm=\"pinot\"");

    WebApplicationException denied = expectThrows(WebApplicationException.class,
        () -> ServerResourceUtils.validateDataAccess(factory(() -> false), "orders_OFFLINE", headers()));
    assertEquals(denied.getResponse().getStatus(), 403);

    WebApplicationException failure = expectThrows(WebApplicationException.class,
        () -> ServerResourceUtils.validateDataAccess(factory(() -> {
          throw new IllegalStateException("boom");
        }), "orders_OFFLINE", headers()));
    assertEquals(failure.getResponse().getStatus(), 500);
  }
}
