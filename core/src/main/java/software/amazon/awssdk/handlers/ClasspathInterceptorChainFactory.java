/*
 * Copyright 2010-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package software.amazon.awssdk.handlers;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import software.amazon.awssdk.AmazonClientException;
import software.amazon.awssdk.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.util.ClassLoaderHelper;

/**
 * Factory for creating request/response handler chains from the classpath.
 */
public final class ClasspathInterceptorChainFactory {

    private static final String GLOBAL_INTERCEPTOR_PATH = "software/amazon/awssdk/global/handlers/execution.interceptors";

    /**
     * Constructs a new request handler chain by analyzing the specified classpath resource.
     *
     * @param resource The resource to load from the classpath containing the list of request handlers to instantiate.
     * @return A list of request handlers based on the handlers referenced in the specified resource.
     */
    public List<ExecutionInterceptor> getInterceptors(String resource) {
        return createExecutionInterceptorFromResource(getClass().getResource(resource)).collect(Collectors.toList());
    }

    /**
     * Load the global handlers by reading the global execution interceptors resource.
     */
    public List<ExecutionInterceptor> getGlobalInterceptors() {
        try {
            return createExecutionInterceptorsFromResources(ExecutionInterceptor.class.getClassLoader()
                                                                                      .getResources(GLOBAL_INTERCEPTOR_PATH))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            throw new AmazonClientException("Unable to instantiate execution interceptor chain.", e);
        }
    }

    private Stream<ExecutionInterceptor> createExecutionInterceptorsFromResources(Enumeration<URL> resources) {
        if (resources == null) {
            return Stream.empty();
        }

        return Collections.list(resources).stream().flatMap(this::createExecutionInterceptorFromResource);
    }

    private Stream<ExecutionInterceptor> createExecutionInterceptorFromResource(URL resource) {
        try {
            if (resource == null) {
                return Stream.empty();
            }

            return Files.readAllLines(Paths.get(resource.toURI())).stream()
                        .map(this::createExecutionInterceptor)
                        .filter(Objects::nonNull);
        } catch (IOException | URISyntaxException e) {
            throw new AmazonClientException("Unable to instantiate execution interceptor chain.", e);
        }
    }

    private ExecutionInterceptor createExecutionInterceptor(String interceptorClassName) {
        interceptorClassName = interceptorClassName.trim();
        if (interceptorClassName.equals("")) {
            return null;
        }

        try {
            Class<?> executionInterceptorClass = ClassLoaderHelper.loadClass(interceptorClassName,
                                                                             ExecutionInterceptor.class, getClass());
            Object executionInterceptorObject = executionInterceptorClass.newInstance();

            if (executionInterceptorObject instanceof ExecutionInterceptor) {
                return (ExecutionInterceptor) executionInterceptorObject;
            } else {
                throw new AmazonClientException("Unable to instantiate request handler chain for client. Listed request handler "
                                                + "('" + interceptorClassName + "') does not implement the " +
                                                ExecutionInterceptor.class + " API.");
            }
        } catch (IllegalAccessException | ClassNotFoundException | InstantiationException e) {
            throw new AmazonClientException("Unable to instantiate executor interceptor for client.", e);
        }
    }
}
