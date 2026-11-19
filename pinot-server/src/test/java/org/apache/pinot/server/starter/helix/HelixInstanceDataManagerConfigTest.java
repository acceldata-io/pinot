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
package org.apache.pinot.server.starter.helix;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.testng.annotations.Test;

import static org.apache.pinot.spi.utils.CommonConstants.Server.INSTANCE_ID;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;


public class HelixInstanceDataManagerConfigTest {

  @Test
  public void testSecretsAreMaskedInTheStartLog()
      throws ConfigurationException {
    String secret = "s3cr3t-value-never-logged";
    Map<String, Object> props = new HashMap<>();
    props.put(INSTANCE_ID, "testInstance");
    props.put("auth.client.secret", secret);
    props.put("auth.token", "Basic " + secret);
    props.put("auth.jar.dir", "/opt/pinot/auth-handlers/samples");

    List<String> lines = new CopyOnWriteArrayList<>();
    AbstractAppender appender = new AbstractAppender("capture", null, null, true, Property.EMPTY_ARRAY) {
      @Override
      public void append(LogEvent event) {
        lines.add(event.getMessage().getFormattedMessage());
      }
    };
    appender.start();
    LoggerContext context = (LoggerContext) LogManager.getContext(false);
    Configuration configuration = context.getConfiguration();
    String loggerName = HelixInstanceDataManagerConfig.class.getName();
    LoggerConfig loggerConfig = new LoggerConfig(loggerName, Level.INFO, false);
    loggerConfig.addAppender(appender, Level.INFO, null);
    configuration.addLogger(loggerName, loggerConfig);
    context.updateLoggers();
    try {
      new HelixInstanceDataManagerConfig(new PinotConfiguration(props));
    } finally {
      configuration.removeLogger(loggerName);
      context.updateLoggers();
      appender.stop();
    }

    assertFalse(lines.isEmpty(), "the configuration is logged at start");
    for (String line : lines) {
      assertFalse(line.contains(secret), "secret in the log: " + line);
    }
    assertTrue(lines.contains("InstanceDataManagerConfig, key: auth.client.secret , value: *****"), lines.toString());
    assertTrue(lines.contains("InstanceDataManagerConfig, key: auth.token , value: *****"), lines.toString());
    assertTrue(lines.contains("InstanceDataManagerConfig, key: auth.jar.dir , value: /opt/pinot/auth-handlers/samples"),
        lines.toString());
  }

  @Test
  public void testTierConfigsWithMultipleTiers() throws ConfigurationException {
    Map<String, Object> props = new HashMap<>();
    props.put(INSTANCE_ID, "testInstance");
    props.put("tierConfigs.tierNames", "tier1,tier2");
    props.put("tierConfigs.tier1.storage", "local");
    props.put("tierConfigs.tier1.compression", "gzip");
    props.put("tierConfigs.tier2.storage", "remote");
    props.put("tierConfigs.tier2.compression", "lz4");
    props.put("tierConfigs.tier2.client", "s3");

    PinotConfiguration pinotConfiguration = new PinotConfiguration(props);
    HelixInstanceDataManagerConfig config = new HelixInstanceDataManagerConfig(pinotConfiguration);

    Map<String, Map<String, String>> tierConfigs = config.getTierConfigs();
    assertEquals(tierConfigs.size(), 2, "Should have exactly two tier configs");

    Map<String, String> tier1Config = tierConfigs.get("tier1");
    assertEquals(tier1Config.get("storage"), "local");
    assertEquals(tier1Config.get("compression"), "gzip");
    assertEquals(tier1Config.size(), 2, "tier1 should have 2 properties");

    Map<String, String> tier2Config = tierConfigs.get("tier2");
    assertEquals(tier2Config.get("storage"), "remote");
    assertEquals(tier2Config.get("compression"), "lz4");
    assertEquals(tier2Config.get("client"), "s3");
    assertEquals(tier2Config.size(), 3, "tier2 should have 3 properties");
  }

  @Test
  public void testDefaultTierConfigsWithNoSpecificTiers() throws ConfigurationException {
    Map<String, Object> props = new HashMap<>();
    props.put(INSTANCE_ID, "testInstance");
    // Set default tier configs but no specific tiers
    props.put("defaultTierConfigs.storage", "s3");
    props.put("defaultTierConfigs.compression", "gzip");

    // No tier names specified
    PinotConfiguration pinotConfiguration = new PinotConfiguration(props);
    HelixInstanceDataManagerConfig config = new HelixInstanceDataManagerConfig(pinotConfiguration);

    Map<String, Map<String, String>> tierConfigs = config.getTierConfigs();
    // tier will get the default value
    Map<String, String> tier1Config = tierConfigs.get("tier1");
    assertEquals(tier1Config.get("storage"), "s3");
    assertEquals(tier1Config.get("compression"), "gzip");
  }

  @Test
  public void testDefaultTierConfigsAppliedToAllTiers() throws ConfigurationException {
    Map<String, Object> props = new HashMap<>();
    props.put(INSTANCE_ID, "testInstance");
    // Set default tier configs that should apply to all tiers
    props.put("defaultTierConfigs.storage", "s3");
    props.put("defaultTierConfigs.compression", "gzip");

    // Define two tiers
    props.put("tierConfigs.tierNames", "hotTier,coldTier");
    // hotTier has no specific configs - should get only defaults
    // coldTier overrides one default and adds a new property
    props.put("tierConfigs.coldTier.compression", "lz4"); // override default
    props.put("tierConfigs.coldTier.tag", "remote"); // additional property

    PinotConfiguration pinotConfiguration = new PinotConfiguration(props);
    HelixInstanceDataManagerConfig config = new HelixInstanceDataManagerConfig(pinotConfiguration);

    Map<String, Map<String, String>> tierConfigs = config.getTierConfigs();
    assertEquals(tierConfigs.size(), 2, "Should have exactly two tier configs");

    // hotTier should have all default configs
    Map<String, String> hotTierConfig = tierConfigs.get("hotTier");
    assertEquals(hotTierConfig.get("storage"), "s3");
    assertEquals(hotTierConfig.get("compression"), "gzip");
    assertEquals(hotTierConfig.size(), 2, "hotTier should have 2 default properties");

    // coldTier should have defaults + overrides + additional properties
    Map<String, String> coldTierConfig = tierConfigs.get("coldTier");
    assertEquals(coldTierConfig.get("storage"), "s3"); // from default
    assertEquals(coldTierConfig.get("compression"), "lz4"); // overridden
    assertEquals(coldTierConfig.get("tag"), "remote"); // additional
    assertEquals(coldTierConfig.size(), 3, "coldTier should have 3 properties");
  }
}
