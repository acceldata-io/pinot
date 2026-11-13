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

import io.grpc.{ManagedChannelBuilder, Metadata, Status, StatusRuntimeException}
import io.grpc.stub.MetadataUtils
import org.apache.pinot.common.datatable.{DataTable, DataTableFactory}
import org.apache.pinot.common.proto.PinotQueryServerGrpc
import org.apache.pinot.common.proto.Server.{ServerRequest, ServerResponse}
import org.apache.pinot.connector.spark.common.{Logging, PinotDataSourceReadOptions}
import org.apache.pinot.connector.spark.common.partition.PinotSplit
import org.apache.pinot.spi.config.table.TableType

import java.io.Closeable
import java.net.URI
import java.util.Locale
import scala.collection.JavaConverters._

/**
 * Data fetcher from Pinot Grpc server for specific segments.
 * Eg: offline-server1: segment1, segment2, segment3
 */
private[reader] class PinotGrpcServerDataFetcher(pinotSplit: PinotSplit, readOptions: PinotDataSourceReadOptions)
  extends Logging with Closeable {

  private val (channelHost, channelPort) = {
    if (readOptions.proxyEnabled && readOptions.grpcProxyUri.nonEmpty) {
      val proxyUri = readOptions.grpcProxyUri.get
      val (hostStr, portStr) = org.apache.pinot.connector.spark.common.NetUtils.parseHostPort(proxyUri, readOptions.useHttps)
      (hostStr, portStr.toInt)
    } else {
      (pinotSplit.serverAndSegments.serverHost, pinotSplit.serverAndSegments.serverGrpcPort)
    }
  }

  // Debug: Print out channel host and port
  logDebug(s"PinotGrpcServerDataFetcher connecting to host: $channelHost, port: $channelPort")
  private val baseChannelBuilder = ManagedChannelBuilder
    .forAddress(channelHost, channelPort)
    .maxInboundMessageSize(Math.min(readOptions.grpcMaxInboundMessageSize, Int.MaxValue.toLong).toInt)
    .asInstanceOf[ManagedChannelBuilder[_]]

  private val channel = {
    val builder =
      if (readOptions.grpcUsePlainText) baseChannelBuilder.usePlaintext()
      else baseChannelBuilder
    builder.build()
  }

  private val credentials = readOptions.credentials

  // A stub carrying the current credentials as call headers (for the proxy), and proxy forwarding headers when the
  // proxy is enabled. Built per request: credentials may be renewed during a long read.
  private def pinotServerBlockingStub(authHeaders: Seq[(String, String)]): PinotQueryServerGrpc.PinotQueryServerBlockingStub = {
    val baseStub = PinotQueryServerGrpc.newBlockingStub(channel)
    if (readOptions.proxyEnabled && readOptions.grpcProxyUri.nonEmpty) {
      val md = new Metadata()
      val forwardHostKey = Metadata.Key.of("forward_host", Metadata.ASCII_STRING_MARSHALLER)
      val forwardPortKey = Metadata.Key.of("forward_port", Metadata.ASCII_STRING_MARSHALLER)
      md.put(forwardHostKey, pinotSplit.serverAndSegments.serverHost)
      md.put(forwardPortKey, pinotSplit.serverAndSegments.serverGrpcPort.toString)
      authHeaders.foreach { case (name, value) =>
        md.put(Metadata.Key.of(name.toLowerCase(Locale.ROOT), Metadata.ASCII_STRING_MARSHALLER), value)
      }
      baseStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(md))
    } else baseStub
  }

  private def submit(): java.util.Iterator[ServerResponse] = {
    val authHeaders = credentials.currentHeaders()
    val requestBuilder = ServerRequest.newBuilder()
      .putMetadata("enableStreaming", "true")
      // Also include forwarding info in request metadata for compatibility with proxies that inspect payload
      .putMetadata("FORWARD_HOST", pinotSplit.serverAndSegments.serverHost)
      .putMetadata("FORWARD_PORT", pinotSplit.serverAndSegments.serverGrpcPort.toString)
    // The server authenticates gRPC queries with the request metadata (lower-case keys), not with call headers
    authHeaders.foreach { case (name, value) =>
      requestBuilder.putMetadata(name.toLowerCase(Locale.ROOT), value)
    }
    val request = requestBuilder
      .addAllSegments(pinotSplit.serverAndSegments.segments.asJava)
      .setSql(
        pinotSplit.serverAndSegments.serverType match {
          case TableType.OFFLINE =>
            pinotSplit.query.offlineSelectQuery
          case TableType.REALTIME =>
            pinotSplit.query.realtimeSelectQuery
        }
      )
      .build()
    val responses = pinotServerBlockingStub(authHeaders).submit(request)
    // The server checks access before it streams anything: surface a refusal here, not while Spark consumes rows
    responses.hasNext
    responses
  }

  def fetchData(): Iterator[DataTable] = {
    val serverResponse = try {
      try {
        submit()
      } catch {
        // Credentials rejected (e.g. a token revoked before its expiry): retry once if the provider renewed them
        case e: StatusRuntimeException
          if e.getStatus.getCode == Status.Code.UNAUTHENTICATED && credentials.onUnauthorized() =>
          logInfo("Pinot server refused the credentials, retrying once with renewed credentials")
          submit()
      }
    } catch {
      case e: StatusRuntimeException =>
        logError(s"Caught exception when reading data from ${pinotSplit.serverAndSegments.serverHost}:${pinotSplit.serverAndSegments.serverGrpcPort}: ${e}")
        throw e
    }
    val dataTables = for {
      serverResponse <- serverResponse.asScala
      if serverResponse.getMetadataMap.get("responseType") == "data"
    } yield DataTableFactory.getDataTable(serverResponse.getPayload.toByteArray)

    dataTables.filter(_.getNumberOfRows > 0)
  }

  def close(): Unit = {
    if (!channel.isShutdown) {
      channel.shutdown()
      logInfo("Pinot server connection closed")
    }
  }
}

object PinotGrpcServerDataFetcher {
  def apply(pinotSplit: PinotSplit, readOptions: PinotDataSourceReadOptions): PinotGrpcServerDataFetcher = {
    new PinotGrpcServerDataFetcher(pinotSplit, readOptions)
  }
}
