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
package org.apache.pinot.controller.api.resources;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import org.apache.pinot.common.utils.SimpleHttpErrorInfo;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;


public class WebApplicationExceptionMapperTest {
  private final WebApplicationExceptionMapper _mapper = new WebApplicationExceptionMapper();

  @Test
  public void testAuthenticationChallengeIsKept() {
    Response response =
        _mapper.toResponse(new NotAuthorizedException("Missing credential", "Basic realm=\"pinot\""));
    assertEquals(response.getStatus(), 401);
    assertEquals(response.getHeaderString("WWW-Authenticate"), "Basic realm=\"pinot\"");
    assertEquals(((SimpleHttpErrorInfo) response.getEntity()).getError(), "Missing credential");
  }

  @Test
  public void testStatusAndMessage() {
    Response response = _mapper.toResponse(new WebApplicationException("Not here", Response.Status.NOT_FOUND));
    assertEquals(response.getStatus(), 404);
    assertEquals(((SimpleHttpErrorInfo) response.getEntity()).getCode(), 404);
    assertNull(response.getHeaderString("WWW-Authenticate"));
    Response error = _mapper.toResponse(new IllegalStateException("boom"));
    assertEquals(error.getStatus(), 500);
    assertEquals(((SimpleHttpErrorInfo) error.getEntity()).getError(), "boom");
  }
}
