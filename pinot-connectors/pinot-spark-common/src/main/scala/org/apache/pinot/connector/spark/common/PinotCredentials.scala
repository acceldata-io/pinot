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

import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

import org.apache.pinot.common.auth.{AuthConfig, AuthProviderUtils}
import org.apache.pinot.spi.auth.AuthProvider

import scala.collection.JavaConverters._

/**
 * The credentials the connector sends to Pinot, from the read options: either a fixed token (`authToken`, optionally
 * with `authHeader`), or an auth provider configured with `authConfig.*` options, which obtains current credentials for
 * every request. With a provider that renews tokens (e.g. Pinot's OAuth 2.0 provider) a read that runs longer than a
 * token's lifetime keeps working.
 *
 * Instances are serialized to the executors with the read options; each JVM (driver, executor) creates the provider
 * once per configuration and shares it between tasks. Thread-safe.
 *
 * @param authConfig the provider settings (keys without the `authConfig.` prefix, e.g. `provider.class`,
 *                   `source`, `token.url`); empty for a fixed token or no authentication
 */
private[pinot] case class PinotCredentials(authHeader: Option[String] = None,
                                           authToken: Option[String] = None,
                                           authConfig: Map[String, String] = Map.empty) {

  /** The headers to send with a request made now. */
  def currentHeaders(): Seq[(String, String)] = {
    if (authConfig.nonEmpty) {
      PinotCredentials.provider(authConfig).getRequestHeaders.asScala.toSeq.collect {
        case (name, value) if value != null => name -> value.toString
      }
    } else {
      AuthUtils.buildAuthHeader(authHeader, authToken).toSeq
    }
  }

  /**
   * Pinot answered 401 to a request with the current credentials (e.g. the token was revoked). Lets the provider drop
   * them.
   *
   * @return true if the next request carries new credentials, so that retrying once is worthwhile
   */
  def onUnauthorized(): Boolean =
    authConfig.nonEmpty && PinotCredentials.provider(authConfig).onUnauthorized()

  // Never print settings or tokens: they may hold secrets
  override def toString: String =
    if (authConfig.nonEmpty) "PinotCredentials(provider)"
    else if (authToken.nonEmpty) "PinotCredentials(token)"
    else "PinotCredentials(none)"
}

private[pinot] object PinotCredentials {
  /** Read option prefix of the auth provider settings. */
  val AUTH_CONFIG_PREFIX = "authConfig."

  val NONE: PinotCredentials = PinotCredentials()

  // One provider per configuration and JVM; providers keep their tokens, so tasks share one token
  private val providers = new ConcurrentHashMap[Map[String, String], AuthProvider]()

  private[common] def provider(authConfig: Map[String, String]): AuthProvider =
    providers.computeIfAbsent(authConfig, config => {
      val properties = new java.util.HashMap[String, Object]()
      config.foreach { case (key, value) => properties.put(key, value) }
      AuthProviderUtils.makeAuthProvider(new AuthConfig(properties))
    })

  /** The `authConfig.*` options with the prefix removed. Option names are case-insensitive. */
  def authConfigFrom(options: java.util.Map[String, String]): Map[String, String] = {
    val prefix = AUTH_CONFIG_PREFIX.toLowerCase(Locale.ROOT)
    options.asScala.collect {
      case (key, value) if key.toLowerCase(Locale.ROOT).startsWith(prefix) && key.length > prefix.length && value != null =>
        key.substring(prefix.length) -> value
    }.toMap
  }

  /** For tests: forget the providers. */
  private[common] def clearProviders(): Unit = providers.clear()
}
