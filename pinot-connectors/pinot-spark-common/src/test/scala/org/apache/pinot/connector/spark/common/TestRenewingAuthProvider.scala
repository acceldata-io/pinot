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
package org.apache.pinot.connector.spark.common

import java.util.concurrent.atomic.AtomicInteger

import org.apache.pinot.common.auth.AuthConfig
import org.apache.pinot.spi.auth.AuthProvider

/**
 * Test auth provider whose token changes over time, like an OAuth 2.0 provider that renews tokens: the current token is
 * `tok-<generation>`; tests advance the generation to simulate expiry, and a 401 makes it advance too.
 */
class TestRenewingAuthProvider(authConfig: AuthConfig) extends AuthProvider {
  TestRenewingAuthProvider.instances.incrementAndGet()

  override def getRequestHeaders: java.util.Map[String, AnyRef] = {
    val headers = new java.util.HashMap[String, AnyRef]()
    headers.put("Authorization", getTaskToken)
    headers
  }

  override def getTaskToken: String = "Bearer " + TestRenewingAuthProvider.currentToken

  override def onUnauthorized(): Boolean = {
    TestRenewingAuthProvider.generation.incrementAndGet()
    true
  }
}

object TestRenewingAuthProvider {
  val generation = new AtomicInteger(1)
  val instances = new AtomicInteger()

  def currentToken: String = "tok-" + generation.get()

  def reset(): Unit = {
    generation.set(1)
    instances.set(0)
    PinotCredentials.clearProviders()
  }
}
