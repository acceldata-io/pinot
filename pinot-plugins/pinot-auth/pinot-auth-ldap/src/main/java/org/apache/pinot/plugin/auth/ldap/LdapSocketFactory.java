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
package org.apache.pinot.plugin.auth.ldap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;


/// The TLS socket factory of LDAPS connections when a truststore is configured. JNDI accepts only a class name
/// (`java.naming.ldap.factory.socket`) and calls its static `getDefault()` while it opens the connection, in the thread
/// that creates the context; [LdapDirectory] sets the factory of its truststore for that thread around each context
/// creation, so several authenticators (or tests) with different truststores do not interfere.
///
/// Host name verification stays on: JNDI sets the `LDAPS` endpoint identification on the sockets it gets from here.
public final class LdapSocketFactory extends SSLSocketFactory {
  private static final ThreadLocal<SSLSocketFactory> CURRENT = new ThreadLocal<>();

  private final SSLSocketFactory _delegate;

  private LdapSocketFactory(SSLSocketFactory delegate) {
    _delegate = delegate;
  }

  /// Called by JNDI.
  public static SocketFactory getDefault() {
    SSLSocketFactory current = CURRENT.get();
    return new LdapSocketFactory(current != null ? current : (SSLSocketFactory) SSLSocketFactory.getDefault());
  }

  static void set(SSLSocketFactory factory) {
    CURRENT.set(factory);
  }

  static void clear() {
    CURRENT.remove();
  }

  @Override
  public String[] getDefaultCipherSuites() {
    return _delegate.getDefaultCipherSuites();
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return _delegate.getSupportedCipherSuites();
  }

  @Override
  public Socket createSocket()
      throws IOException {
    return _delegate.createSocket();
  }

  @Override
  public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
      throws IOException {
    return _delegate.createSocket(socket, host, port, autoClose);
  }

  @Override
  public Socket createSocket(String host, int port)
      throws IOException {
    return _delegate.createSocket(host, port);
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
      throws IOException {
    return _delegate.createSocket(host, port, localHost, localPort);
  }

  @Override
  public Socket createSocket(InetAddress host, int port)
      throws IOException {
    return _delegate.createSocket(host, port);
  }

  @Override
  public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
      throws IOException {
    return _delegate.createSocket(address, port, localAddress, localPort);
  }
}
