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
package org.apache.pinot.minion.event;

import org.apache.pinot.minion.executor.MinionTaskZkMetadataManager;
import org.apache.pinot.spi.tasks.MinionTaskObserverStorageManager;


/**
 * Factory for {@link MinionEventObserver}.
 */
public interface MinionEventObserverFactory {

  /**
   * Initializes the task executor factory.
   */
  void init(MinionTaskZkMetadataManager zkMetadataManager);

  /**
   * Initializes the task executor factory with the specified {@link MinionTaskObserverStorageManager}
   * to manage the storage of stats recorded by the {@link MinionEventObserver}.
   */
  void init(MinionTaskZkMetadataManager zkMetadataManager, MinionTaskObserverStorageManager taskProgressManager);

  /**
   * Returns the task type of the event observer.
   */
  String getTaskType();

  /**
   * Creates a new task event observer.
   */
  MinionEventObserver create();
}
