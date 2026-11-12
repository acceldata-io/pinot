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
package org.apache.pinot.controller.api.access;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import org.apache.pinot.controller.ControllerConf;
import org.apache.pinot.core.auth.Actions;
import org.apache.pinot.core.auth.Authorize;
import org.apache.pinot.core.auth.ManualAuthorization;
import org.apache.pinot.core.auth.TargetType;
import org.apache.pinot.spi.utils.PinotReflectionUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;


/**
 * Build-time completeness check for the controller's fine-grained authorization.
 *
 * <p>Every REST endpoint registered under the default controller resource package must either carry
 * {@link Authorize} (checked by {@code FineGrainedAuthUtils.validateFineGrainedAuth}) or be explicitly marked
 * {@link ManualAuthorization} (the resource method does its own check). Every {@link Authorize} must be internally
 * consistent: its action must be a declared {@link Actions} constant of the matching {@link TargetType}, and a
 * {@link TargetType#TABLE} target must name a {@code paramName} that the method actually declares as a path or query
 * parameter, otherwise the filter fails the request with HTTP 500 at runtime.
 *
 * <p>Endpoints that are known not to satisfy these rules today are listed explicitly below. The lists are compared
 * for exact equality, so the test fails both when a new endpoint is added without an annotation and when a listed
 * endpoint is fixed but not removed from its list. The lists are expected to be emptied as the annotation gaps are
 * closed; the manual list is expected to only ever shrink. Running with the system property
 * {@value #STRICT_PROPERTY} set to {@code true} ignores the known lists, so the test then fails on every remaining
 * gap and reports all of them.
 */
@Test(groups = "stateless")
public class FineGrainedAuthorizationCoverageTest {
  /** System property; when {@code true} the known-gap lists are treated as empty. */
  public static final String STRICT_PROPERTY = "pinot.authz.coverage.strict";
  private static final boolean STRICT = Boolean.getBoolean(STRICT_PROPERTY);

  /** Endpoints with neither {@link Authorize} nor {@link ManualAuthorization}. Must become empty. */
  private static final List<String> KNOWN_UNANNOTATED_ENDPOINTS = Collections.emptyList();

  /**
   * Endpoints with neither annotation that the {@link AuthenticationFilter} serves without authentication on purpose.
   * The UI landing page has to load before the user can sign in.
   */
  private static final List<String> KNOWN_PUBLIC_ENDPOINTS = Collections.singletonList("GET /");

  /** Endpoints that authorize inside the resource method. Each one must keep an explicit reason to stay manual. */
  private static final List<String> KNOWN_MANUAL_ENDPOINTS = Arrays.asList(
      "POST /logicalTables",
      "POST /sql",
      "GET /sql",
      "GET /timeseries/api/v1/query_range",
      "POST /query/timeseries",
      "POST /schemas",
      "POST /schemas",
      "POST /schemas/validate",
      "POST /schemas/validate",
      "GET /schemas/fieldSpec",
      "POST /tables",
      "POST /tables/validate",
      "PUT /tables/{tableName}/state",
      "POST /tableConfigs",
      "POST /tableConfigs/validate");

  /** TABLE-scoped {@link Authorize} without a {@code paramName}: the filter answers HTTP 500. Must become empty. */
  private static final List<String> KNOWN_TABLE_TARGET_WITHOUT_PARAM = Collections.emptyList();

  /** CLUSTER-scoped {@link Authorize} that carries a {@code paramName} the filter ignores. Must become empty. */
  private static final List<String> KNOWN_CLUSTER_TARGET_WITH_PARAM = Collections.emptyList();

  private final List<Endpoint> _endpoints = new ArrayList<>();

  @BeforeClass
  public void collectEndpoints() {
    Set<Class<?>> resourceClasses = PinotReflectionUtils.getClassesThroughReflection(
        ControllerConf.DEFAULT_CONTROLLER_RESOURCE_PACKAGES, ".*", Path.class);
    assertFalse(resourceClasses.isEmpty(), "No JAX-RS resource classes found under "
        + ControllerConf.DEFAULT_CONTROLLER_RESOURCE_PACKAGES);
    for (Class<?> resourceClass : resourceClasses) {
      if (!isProductionResource(resourceClass)) {
        continue;
      }
      Path classPath = resourceClass.getAnnotation(Path.class);
      String classPathValue = classPath == null ? "" : classPath.value();
      for (Method method : resourceClass.getDeclaredMethods()) {
        String httpMethod = httpMethodOf(method);
        if (httpMethod == null || !Modifier.isPublic(method.getModifiers())) {
          continue;
        }
        Path methodPath = method.getAnnotation(Path.class);
        String fullPath = joinPaths(classPathValue, methodPath == null ? "" : methodPath.value());
        _endpoints.add(new Endpoint(resourceClass, method, httpMethod + " " + fullPath));
      }
    }
    assertTrue(_endpoints.size() > 200, "Unexpectedly few controller endpoints found: " + _endpoints.size());
  }

  @Test
  public void testEveryEndpointIsAnnotatedOrExplicitlyManual() {
    List<String> unannotated = new ArrayList<>();
    List<String> publicEndpoints = new ArrayList<>();
    List<String> manual = new ArrayList<>();
    List<String> both = new ArrayList<>();
    for (Endpoint endpoint : _endpoints) {
      boolean authorize = endpoint._method.isAnnotationPresent(Authorize.class);
      boolean manualAuth = endpoint._method.isAnnotationPresent(ManualAuthorization.class);
      if (authorize && manualAuth) {
        both.add(endpoint.describe());
      } else if (manualAuth) {
        manual.add(endpoint._id);
      } else if (!authorize) {
        String path = endpoint._id.substring(endpoint._id.indexOf(' ') + 1);
        if (AuthenticationFilter.isUnprotectedPath(path.startsWith("/") ? path.substring(1) : path)) {
          publicEndpoints.add(endpoint._id);
        } else {
          unannotated.add(endpoint._id);
        }
      }
    }
    assertTrue(both.isEmpty(), "Endpoints carry both @Authorize and @ManualAuthorization: " + both);
    assertSameEndpoints(unannotated, KNOWN_UNANNOTATED_ENDPOINTS,
        "Endpoints without @Authorize or @ManualAuthorization");
    assertSameEndpoints(manual, KNOWN_MANUAL_ENDPOINTS, "Endpoints with @ManualAuthorization");
    // Not subject to the strict mode: these stay public by design, the list only makes any new one visible.
    assertEquals(sorted(publicEndpoints), sorted(KNOWN_PUBLIC_ENDPOINTS),
        "Endpoints served without authentication by AuthenticationFilter");
  }

  @Test
  public void testAuthorizeActionIsADeclaredActionOfItsTargetType() {
    Map<TargetType, Set<String>> declaredActions = declaredActions();
    List<String> unknown = new ArrayList<>();
    for (Endpoint endpoint : _endpoints) {
      Authorize authorize = endpoint._method.getAnnotation(Authorize.class);
      if (authorize == null) {
        continue;
      }
      Set<String> actions = declaredActions.get(authorize.targetType());
      assertTrue(actions != null, "No Actions class is known for target type " + authorize.targetType()
          + " used by " + endpoint.describe());
      if (!actions.contains(authorize.action())) {
        unknown.add(endpoint.describe() + " -> " + authorize.targetType() + "/" + authorize.action());
      }
    }
    assertTrue(unknown.isEmpty(), "@Authorize actions that are not declared in Actions for their target type: "
        + unknown);
  }

  @Test
  public void testTableTargetNamesAParameterTheMethodDeclares() {
    List<String> missingParam = new ArrayList<>();
    List<String> undeclaredParam = new ArrayList<>();
    for (Endpoint endpoint : _endpoints) {
      Authorize authorize = endpoint._method.getAnnotation(Authorize.class);
      if (authorize == null || authorize.targetType() != TargetType.TABLE) {
        continue;
      }
      if (authorize.paramName().isEmpty()) {
        missingParam.add(endpoint._id);
      } else if (!declaredParamNames(endpoint._method).contains(authorize.paramName())) {
        undeclaredParam.add(endpoint.describe() + " paramName=" + authorize.paramName() + " declared="
            + declaredParamNames(endpoint._method));
      }
    }
    assertSameEndpoints(missingParam, KNOWN_TABLE_TARGET_WITHOUT_PARAM,
        "TABLE-scoped @Authorize without paramName (the filter returns HTTP 500 for these)");
    assertTrue(undeclaredParam.isEmpty(),
        "TABLE-scoped @Authorize whose paramName is not a @PathParam or @QueryParam of the method: "
            + undeclaredParam);
  }

  @Test
  public void testClusterTargetDoesNotCarryAnIgnoredParameter() {
    List<String> withParam = new ArrayList<>();
    for (Endpoint endpoint : _endpoints) {
      Authorize authorize = endpoint._method.getAnnotation(Authorize.class);
      if (authorize != null && authorize.targetType() == TargetType.CLUSTER && !authorize.paramName().isEmpty()) {
        withParam.add(endpoint._id);
      }
    }
    assertSameEndpoints(withParam, KNOWN_CLUSTER_TARGET_WITH_PARAM,
        "CLUSTER-scoped @Authorize carrying a paramName (ignored by the filter; probably meant to be TABLE)");
  }

  @Test
  public void testDeclaredActionsAreUniquePerTargetType() {
    for (Class<?> actionsClass : Arrays.asList(Actions.Cluster.class, Actions.Table.class)) {
      Map<String, List<String>> byValue = new HashMap<>();
      for (Field field : actionsClass.getDeclaredFields()) {
        if (isActionConstant(field)) {
          byValue.computeIfAbsent(constantValue(field), k -> new ArrayList<>()).add(field.getName());
        }
      }
      Map<String, List<String>> duplicates = byValue.entrySet().stream()
          .filter(e -> e.getValue().size() > 1)
          .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
      assertTrue(duplicates.isEmpty(), "Duplicate action values in " + actionsClass.getName() + ": " + duplicates);
      assertFalse(byValue.isEmpty(), "No action constants found in " + actionsClass.getName());
    }
  }

  /**
   * Every declared action, per target type. Backends that map actions to permissions (native rules, Ranger access
   * types) must cover exactly this set; their mapping tests are expected to build on this method.
   */
  public static Map<TargetType, Set<String>> declaredActions() {
    Map<TargetType, Set<String>> actions = new TreeMap<>();
    actions.put(TargetType.CLUSTER, constantValues(Actions.Cluster.class));
    actions.put(TargetType.TABLE, constantValues(Actions.Table.class));
    return actions;
  }

  private static Set<String> constantValues(Class<?> actionsClass) {
    Set<String> values = new TreeSet<>();
    for (Field field : actionsClass.getDeclaredFields()) {
      if (isActionConstant(field)) {
        values.add(constantValue(field));
      }
    }
    return values;
  }

  private static boolean isActionConstant(Field field) {
    int modifiers = field.getModifiers();
    return field.getType() == String.class && Modifier.isPublic(modifiers) && Modifier.isStatic(modifiers)
        && Modifier.isFinal(modifiers);
  }

  private static String constantValue(Field field) {
    try {
      return (String) field.get(null);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException("Cannot read action constant " + field, e);
    }
  }

  private static Set<String> declaredParamNames(Method method) {
    Set<String> names = new HashSet<>();
    for (Annotation[] parameterAnnotations : method.getParameterAnnotations()) {
      for (Annotation annotation : parameterAnnotations) {
        if (annotation instanceof PathParam) {
          names.add(((PathParam) annotation).value());
        } else if (annotation instanceof QueryParam) {
          names.add(((QueryParam) annotation).value());
        }
      }
    }
    return names;
  }

  /**
   * Keeps classes that Jersey registers from the production resource package, dropping test-only resources that
   * live on the test classpath (for example the dummy "extra resources" used by the controller tests).
   */
  private static boolean isProductionResource(Class<?> resourceClass) {
    String packageName = resourceClass.getPackage() == null ? "" : resourceClass.getPackage().getName();
    String basePackage = ControllerConf.DEFAULT_CONTROLLER_RESOURCE_PACKAGES;
    if (!packageName.equals(basePackage) && !packageName.startsWith(basePackage + ".")) {
      return false;
    }
    if (resourceClass.getProtectionDomain() != null && resourceClass.getProtectionDomain().getCodeSource() != null
        && resourceClass.getProtectionDomain().getCodeSource().getLocation() != null) {
      String location = resourceClass.getProtectionDomain().getCodeSource().getLocation().toString();
      return !location.contains("test-classes") && !location.contains("-tests.jar");
    }
    return true;
  }

  private static String httpMethodOf(Method method) {
    for (Annotation annotation : method.getAnnotations()) {
      HttpMethod httpMethod = annotation.annotationType().getAnnotation(HttpMethod.class);
      if (httpMethod != null) {
        return httpMethod.value();
      }
    }
    return null;
  }

  private static String joinPaths(String classPath, String methodPath) {
    String joined = "/" + classPath + "/" + methodPath;
    return joined.replaceAll("/+", "/").replaceAll("(?<=.)/$", "");
  }

  private static List<String> sorted(List<String> endpoints) {
    List<String> copy = new ArrayList<>(endpoints);
    Collections.sort(copy);
    return copy;
  }

  private static void assertSameEndpoints(List<String> actual, List<String> expected, String what) {
    List<String> sortedActual = new ArrayList<>(actual);
    List<String> sortedExpected = STRICT ? new ArrayList<>() : new ArrayList<>(expected);
    Collections.sort(sortedActual);
    Collections.sort(sortedExpected);
    List<String> unexpected = new ArrayList<>(sortedActual);
    unexpected.removeAll(sortedExpected);
    List<String> stale = new ArrayList<>(sortedExpected);
    stale.removeAll(sortedActual);
    assertEquals(sortedActual, sortedExpected, what + " differ from the known list. New (fix or add to the list): "
        + unexpected + ". Fixed but still listed (remove from the list): " + stale);
  }

  private static final class Endpoint {
    final Class<?> _resourceClass;
    final Method _method;
    final String _id;

    Endpoint(Class<?> resourceClass, Method method, String id) {
      _resourceClass = resourceClass;
      _method = method;
      _id = id;
    }

    String describe() {
      return _id + " (" + _resourceClass.getSimpleName() + "." + _method.getName() + ")";
    }
  }
}
