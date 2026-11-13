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

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream, ObjectOutputStream}
import java.net.{InetSocketAddress, URI}
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference

import com.sun.net.httpserver.HttpServer
import org.scalatest.BeforeAndAfterEach

import scala.collection.JavaConverters._

class PinotCredentialsTest extends BaseTest with BeforeAndAfterEach {
  private val providerConfig = Map("provider.class" -> classOf[TestRenewingAuthProvider].getName)

  override def beforeEach(): Unit = TestRenewingAuthProvider.reset()

  test("authConfig options are collected without their prefix, case-insensitively") {
    val options = new CaseInsensitiveStringMap(Map(
      "authConfig.provider.class" -> "p",
      "AUTHCONFIG.token.url" -> "https://idp/token",
      "authConfig." -> "ignored",
      "authToken" -> "t",
      "table" -> "tbl").asJava)
    PinotCredentials.authConfigFrom(options) shouldEqual Map("provider.class" -> "p", "token.url" -> "https://idp/token")
  }

  test("a fixed token gives the same header every time and cannot be renewed") {
    val credentials = PinotCredentials(None, Some("abc"))
    credentials.currentHeaders() shouldEqual Seq("Authorization" -> "Bearer abc")
    credentials.onUnauthorized() shouldBe false
    PinotCredentials.NONE.currentHeaders() shouldBe empty
  }

  test("a provider gives the current token for each request and is created once per JVM") {
    val credentials = PinotCredentials(authConfig = providerConfig)
    credentials.currentHeaders() shouldEqual Seq("Authorization" -> "Bearer tok-1")
    TestRenewingAuthProvider.generation.incrementAndGet()
    PinotCredentials(authConfig = providerConfig).currentHeaders() shouldEqual Seq("Authorization" -> "Bearer tok-2")
    TestRenewingAuthProvider.instances.get() shouldEqual 1
  }

  test("credentials survive serialization to executors and never print secrets") {
    val credentials = PinotCredentials(authConfig = providerConfig + ("client.secret" -> "s3cr3t"))
    val bytes = new ByteArrayOutputStream()
    val out = new ObjectOutputStream(bytes)
    out.writeObject(credentials)
    out.close()
    val copy = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray)).readObject()
    copy shouldEqual credentials
    copy.asInstanceOf[PinotCredentials].currentHeaders() shouldEqual Seq("Authorization" -> "Bearer tok-1")
    credentials.toString should not include "s3cr3t"
  }

  test("HTTP requests carry the current token, and a 401 is retried once with a renewed token") {
    val accepted = new AtomicReference[String]("Bearer tok-1")
    val received = new CopyOnWriteArrayList[String]()
    val server = HttpServer.create(new InetSocketAddress("localhost", 0), 0)
    server.createContext("/", exchange => {
      val authorization = exchange.getRequestHeaders.getFirst("Authorization")
      received.add(authorization)
      val (status, body) = if (authorization == accepted.get()) (200, "ok") else (401, "")
      val bytes = body.getBytes(StandardCharsets.UTF_8)
      exchange.sendResponseHeaders(status, if (bytes.isEmpty) -1 else bytes.length)
      if (bytes.nonEmpty) exchange.getResponseBody.write(bytes)
      exchange.close()
    })
    server.start()
    try {
      val uri = new URI(s"http://localhost:${server.getAddress.getPort}/tables")
      val credentials = PinotCredentials(authConfig = providerConfig)
      HttpUtils.sendGetRequest(uri, credentials) shouldEqual "ok"

      // The token expired and the provider renewed it: the next request carries the new one
      TestRenewingAuthProvider.generation.incrementAndGet()
      accepted.set("Bearer tok-2")
      HttpUtils.sendGetRequest(uri, credentials) shouldEqual "ok"

      // The token was revoked before its expiry: 401, renewed, retried once
      accepted.set("Bearer tok-3")
      HttpUtils.sendGetRequest(uri, credentials) shouldEqual "ok"
      received.asScala shouldEqual Seq("Bearer tok-1", "Bearer tok-2", "Bearer tok-2", "Bearer tok-3")

      // A fixed token is not retried
      received.clear()
      val e = intercept[HttpStatusCodeException] {
        HttpUtils.sendGetRequest(uri, PinotCredentials(None, Some("old")))
      }
      e.statusCode shouldEqual 401
      received.asScala shouldEqual Seq("Bearer old")
    } finally {
      server.stop(0)
    }
  }

  test("read options take authConfig.* and hide it when printed") {
    val options = Map(
      PinotDataSourceReadOptions.CONFIG_TABLE_NAME -> "tbl",
      PinotDataSourceReadOptions.CONFIG_TABLE_TYPE -> "offline",
      PinotDataSourceReadOptions.CONFIG_BROKER -> "localhost:8000",
      "authConfig.provider.class" -> classOf[TestRenewingAuthProvider].getName,
      "authConfig.client.secret" -> "s3cr3t")
    val readOptions = PinotDataSourceReadOptions.from(options.asJava)
    readOptions.authConfig shouldEqual Map("provider.class" -> classOf[TestRenewingAuthProvider].getName,
      "client.secret" -> "s3cr3t")
    readOptions.credentials.currentHeaders() shouldEqual Seq("Authorization" -> "Bearer tok-1")
    readOptions.toString should not include "s3cr3t"
  }

  test("read options fail fast when the auth provider cannot be created") {
    val options = Map(
      PinotDataSourceReadOptions.CONFIG_TABLE_NAME -> "tbl",
      PinotDataSourceReadOptions.CONFIG_TABLE_TYPE -> "offline",
      PinotDataSourceReadOptions.CONFIG_BROKER -> "localhost:8000",
      "authConfig.token.url" -> "https://idp/token")
    an[IllegalArgumentException] should be thrownBy PinotDataSourceReadOptions.from(options.asJava)
  }
}
