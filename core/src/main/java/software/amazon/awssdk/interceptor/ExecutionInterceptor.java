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

package software.amazon.awssdk.interceptor;

import software.amazon.awssdk.SdkRequest;
import software.amazon.awssdk.SdkResponse;
import software.amazon.awssdk.config.ClientOverrideConfiguration;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpFullResponse;
import software.amazon.awssdk.interceptor.context.AfterExecutionContext;
import software.amazon.awssdk.interceptor.context.AfterMarshallingContext;
import software.amazon.awssdk.interceptor.context.AfterTransmissionContext;
import software.amazon.awssdk.interceptor.context.AfterUnmarshallingContext;
import software.amazon.awssdk.interceptor.context.BeforeExecutionContext;
import software.amazon.awssdk.interceptor.context.BeforeMarshallingContext;
import software.amazon.awssdk.interceptor.context.BeforeTransmissionContext;
import software.amazon.awssdk.interceptor.context.BeforeUnmarshallingContext;
import software.amazon.awssdk.interceptor.context.FailedExecutionContext;

/**
 * An interceptor that is invoked during the execution lifecycle of a request/response (execution). This can be used to publish
 * metrics, modify a request in-flight, debug request processing, view exceptions, etc.
 *
 * Custom interceptors can be registered when creating a client using {@link ClientOverrideConfiguration#TODO}. Other interceptors
 * may be loaded at runtime from the classpath. TODO: Details?
 *
 * This interface exposes different methods for hooking into different parts of the lifecycle of an execution.
 *
 * Methods are executed in a predictable order, each receiving the information that is known about the message so far as well as
 * a {@link ExecutionAttributes} object for storing data that is specific to a particular execution. TODO: What about retries?
 * <ol>
 *     <li>{@link #beforeExecution} - Read the request before it is modified by other interceptors.</li>
 *     <li>{@link #modifyRequest} - Modify the request object before it is marshalled into an HTTP request.</li>
 *     <li>{@link #beforeMarshalling} - Read the request that has potentially been modified by other request interceptors before
 *     it is marshalled into an HTTP request.</li>
 *     <li>{@link #afterMarshalling} - Read the HTTP request before it is modified by other inteceptors.</li>
 *     <li>{@link #modifyHttpRequest} - Modify the HTTP request object before it is transmitted.</li>
 *     <li>{@link #beforeTransmission} - Read the HTTP request that has potentially been modified by other request interceptors
 *     before it is sent to the service.</li>
 *     <li>{@link #afterTransmission} - Read the HTTP response before it is modified by other interceptors.</li>
 *     <li>{@link #modifyHttpResponse} - Modify the HTTP response object before it is unmarshalled.</li>
 *     <li>{@link #beforeUnmarshalling} - Read the HTTP response that has potentially been modified by other request interceptors
 *     before it is unmarshalled.</li>
 *     <li>{@link #afterUnmarshalling} - Read the response before it is modified by other interceptors.</li>
 *     <li>{@link #modifyResponse} - Modify the response object before before it is returned to the client.</li>
 *     <li>{@link #afterExecution} - Read the response that has potentially been modified by other request interceptors.</li>
 * </ol>
 *
 * An additional {@link #onExecutionFailure} method is provided that is invoked if an execution fails at any point during the
 * lifecycle of a request, including exceptions being thrown from this or other interceptors.
 */
public interface ExecutionInterceptor {
    /**
     * Read a request that has been given to a service client before it is modified by other interceptors.
     *
     * Unlike other interceptor methods, this method is guaranteed to be executed on the thread that is making the service call.
     * This is true even if a non-blocking I/O client is used. This is useful for transferring data that may be stored thread-
     * locally into the execution's {@link ExecutionAttributes}.
     *
     * @param execution The current state of the execution, including the unmodified request from the service client call.
     * @param executionAttributes A mutable set of attributes scoped to one specific request/response cycle that can be used to
     *                            give data to future lifecycle methods.
     */
    default void beforeExecution(BeforeExecutionContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }

    default SdkRequest modifyRequest(BeforeMarshallingContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {
        return execution.request();
    }

    default void beforeMarshalling(BeforeMarshallingContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }

    default void afterMarshalling(AfterMarshallingContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }

    default SdkHttpFullRequest modifyHttpRequest(BeforeTransmissionContext execution,
                                                 ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {
        return execution.httpRequest();
    }

    default void beforeTransmission(BeforeTransmissionContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }

    default void afterTransmission(AfterTransmissionContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }

    default SdkHttpFullResponse modifyHttpResponse(BeforeUnmarshallingContext execution,
                                                   ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {
        return execution.httpResponse();
    }

    default void beforeUnmarshalling(BeforeUnmarshallingContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }

    default void afterUnmarshalling(AfterUnmarshallingContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }

    default SdkResponse modifyResponse(AfterExecutionContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {
        return execution.response();
    }

    default void afterExecution(AfterExecutionContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }

    default void onExecutionFailure(FailedExecutionContext execution, ExecutionAttributes executionAttributes)
            throws ExecutionInterceptorException {

    }
}
