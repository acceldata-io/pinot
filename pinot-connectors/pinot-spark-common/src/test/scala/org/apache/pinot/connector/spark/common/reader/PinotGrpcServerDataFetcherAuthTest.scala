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
package org.apache.pinot.connector.spark.common.reader

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference

import io.grpc.{Server, ServerBuilder, Status}
import io.grpc.stub.StreamObserver
import org.apache.pinot.common.proto.PinotQueryServerGrpc
import org.apache.pinot.common.proto.Server.{ServerRequest, ServerResponse}
import org.apache.pinot.connector.spark.common.{BaseTest, PinotDataSourceReadOptions, TestRenewingAuthProvider}
import org.apache.pinot.connector.spark.common.partition.{PinotServerAndSegments, PinotSplit}
import org.apache.pinot.connector.spark.common.query.ScanQuery
import org.apache.pinot.spi.config.table.TableType
import org.scalatest.BeforeAndAfterEach

import scala.collection.JavaConverters._

/** The gRPC reader sends the current credentials in the request metadata, where the server authenticates queries. */
class PinotGrpcServerDataFetcherAuthTest extends BaseTest with BeforeAndAfterEach {
  private val accepted = new AtomicReference[String]()
  private val received = new CopyOnWriteArrayList[String]()
  private var server: Server = _

  override def beforeEach(): Unit = {
    TestRenewingAuthProvider.reset()
    received.clear()
    accepted.set("Bearer tok-1")
    server = ServerBuilder.forPort(0).addService(new PinotQueryServerGrpc.PinotQueryServerImplBase {
      override def submit(request: ServerRequest, observer: StreamObserver[ServerResponse]): Unit = {
        val authorization = request.getMetadataMap.get("authorization")
        received.add(authorization)
        if (authorization != accepted.get()) {
          observer.onError(Status.UNAUTHENTICATED.withDescription("bad token").asRuntimeException())
        } else {
          observer.onNext(ServerResponse.newBuilder().putMetadata("responseType", "metadata").build())
          observer.onCompleted()
        }
      }
    }).build().start()
  }

  override def afterEach(): Unit = server.shutdownNow()

  private def fetch(readOptions: PinotDataSourceReadOptions): Unit = {
    val split = PinotSplit(ScanQuery("tbl", Some(TableType.OFFLINE), "select * from tbl_OFFLINE", ""),
      PinotServerAndSegments("localhost", "8098", server.getPort, List("seg0"), TableType.OFFLINE))
    val fetcher = PinotGrpcServerDataFetcher(split, readOptions)
    try {
      fetcher.fetchData().toList shouldBe empty
    } finally {
      fetcher.close()
    }
  }

  private def readOptions(options: (String, String)*): PinotDataSourceReadOptions =
    PinotDataSourceReadOptions.from((Map(
      PinotDataSourceReadOptions.CONFIG_TABLE_NAME -> "tbl",
      PinotDataSourceReadOptions.CONFIG_TABLE_TYPE -> "offline",
      PinotDataSourceReadOptions.CONFIG_BROKER -> "localhost:8000",
      PinotDataSourceReadOptions.CONFIG_USE_GRPC_SERVER -> "true") ++ options).asJava)

  test("each query carries the current token; a refused token is renewed and the query retried once") {
    val options = readOptions("authConfig.provider.class" -> classOf[TestRenewingAuthProvider].getName)
    fetch(options)

    // Token renewed by the provider (expiry) between two splits
    TestRenewingAuthProvider.generation.incrementAndGet()
    accepted.set("Bearer tok-2")
    fetch(options)

    // Token revoked: UNAUTHENTICATED, renewed, retried
    accepted.set("Bearer tok-3")
    fetch(options)
    received.asScala shouldEqual Seq("Bearer tok-1", "Bearer tok-2", "Bearer tok-2", "Bearer tok-3")
  }

  test("a fixed token is sent to the server and not retried when refused") {
    fetch(readOptions(PinotDataSourceReadOptions.CONFIG_AUTH_TOKEN -> "tok-1"))
    accepted.set("Bearer other")
    val e = intercept[io.grpc.StatusRuntimeException](fetch(readOptions(PinotDataSourceReadOptions.CONFIG_AUTH_TOKEN
      -> "tok-1")))
    e.getStatus.getCode shouldEqual Status.Code.UNAUTHENTICATED
    received.asScala shouldEqual Seq("Bearer tok-1", "Bearer tok-1")
  }

  test("without authentication options nothing is sent and nothing changes") {
    accepted.set(null)
    fetch(readOptions())
    received.asScala shouldEqual Seq(null)
  }
}
