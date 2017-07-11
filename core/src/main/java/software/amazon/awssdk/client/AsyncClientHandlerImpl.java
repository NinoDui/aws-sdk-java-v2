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

package software.amazon.awssdk.client;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import org.reactivestreams.Subscriber;
import software.amazon.awssdk.Request;
import software.amazon.awssdk.RequestConfig;
import software.amazon.awssdk.SdkBaseException;
import software.amazon.awssdk.SdkRequest;
import software.amazon.awssdk.ServiceAdvancedConfiguration;
import software.amazon.awssdk.annotation.Immutable;
import software.amazon.awssdk.annotation.ReviewBeforeRelease;
import software.amazon.awssdk.annotation.SdkProtectedApi;
import software.amazon.awssdk.annotation.ThreadSafe;
import software.amazon.awssdk.async.AsyncRequestProvider;
import software.amazon.awssdk.config.AsyncClientConfiguration;
import software.amazon.awssdk.config.InternalAdvancedClientOption;
import software.amazon.awssdk.handlers.AwsExecutionAttributes;
import software.amazon.awssdk.http.AmazonAsyncHttpClient;
import software.amazon.awssdk.http.ExecutionContext;
import software.amazon.awssdk.http.HttpResponse;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpFullRequestAdapter;
import software.amazon.awssdk.http.SdkHttpFullResponse;
import software.amazon.awssdk.http.SdkHttpResponseAdapter;
import software.amazon.awssdk.http.async.SdkHttpRequestProvider;
import software.amazon.awssdk.http.async.SdkHttpResponseHandler;
import software.amazon.awssdk.http.async.SyncResponseHandlerAdapter;
import software.amazon.awssdk.interceptor.ExecutionAttributes;
import software.amazon.awssdk.metrics.spi.AwsRequestMetrics;
import software.amazon.awssdk.util.CredentialUtils;
import software.amazon.awssdk.util.Throwables;

/**
 * Default implementation of {@link ClientHandler}.
 */
@Immutable
@ThreadSafe
@SdkProtectedApi
public class AsyncClientHandlerImpl extends AsyncClientHandler {
    private final AsyncClientConfiguration asyncClientConfiguration;
    private final AmazonAsyncHttpClient client;

    @ReviewBeforeRelease("Should this be migrated to use a builder, particularly because it crosses module boundaries?")
    public AsyncClientHandlerImpl(AsyncClientConfiguration asyncClientConfiguration,
                                  ServiceAdvancedConfiguration serviceAdvancedConfiguration) {
        super(asyncClientConfiguration, serviceAdvancedConfiguration);
        this.asyncClientConfiguration = asyncClientConfiguration;
        this.client = AmazonAsyncHttpClient.builder()
                                           .asyncClientConfiguration(asyncClientConfiguration)
                                           .build();
    }

    @Override
    public <InputT extends SdkRequest, OutputT> CompletableFuture<OutputT> execute(
            ClientExecutionParams<InputT, OutputT> executionParams) {
        ExecutionContext executionContext = createExecutionContext(executionParams.getRequestConfig());
        runBeforeExecutionInterceptors(executionContext);
        InputT inputT = runModifyRequestInterceptors(executionContext);

        AwsRequestMetrics awsRequestMetrics = executionContext.awsRequestMetrics();
        awsRequestMetrics.startEvent(AwsRequestMetrics.Field.ClientExecuteTime);
        Request<InputT> request;

        awsRequestMetrics.startEvent(AwsRequestMetrics.Field.RequestMarshallTime);
        try {
            runBeforeMarshallingInterceptors(executionContext);
            request = executionParams.getMarshaller().marshall(inputT);
            request.setAwsRequestMetrics(awsRequestMetrics);
            request.setEndpoint(asyncClientConfiguration.endpoint());

            // TODO: Can any of this be merged into the parent class? There's a lot of duplication here.
            executionContext.executionAttributes().putAttribute(AwsExecutionAttributes.SERVICE_NAME, request.getServiceName());
        } catch (Exception e) {
            endClientExecution(awsRequestMetrics, executionParams.getRequestConfig(), null, null);
            throw e;
        } finally {
            awsRequestMetrics.endEvent(AwsRequestMetrics.Field.RequestMarshallTime);
        }

        addHttpRequest(executionContext, SdkHttpFullRequestAdapter.toHttpFullRequest(request));
        runAfterMarshallingInterceptors(executionContext);
        SdkHttpFullRequest marshalled = runModifyHttpRequestInterceptors(executionContext);

        SdkHttpRequestProvider requestProvider = executionParams.getAsyncRequestProvider() != null ?
                adaptAsyncRequestProvider(executionParams.getAsyncRequestProvider()) : null;

        boolean calculateCrc32FromCompressedData =
                asyncClientConfiguration.overrideConfiguration()
                                        .advancedOption(InternalAdvancedClientOption.CRC32_FROM_COMPRESSED_DATA_ENABLED);

        Function<SdkHttpFullResponse, HttpResponse> responseAdapter
                = r -> SdkHttpResponseAdapter.adapt(calculateCrc32FromCompressedData, marshalled, r);

        SdkHttpResponseHandler<OutputT> responseHandler = resolveResponseHandler(executionParams, responseAdapter,
                                                                                 executionContext.executionAttributes());

        SdkHttpResponseHandler<? extends SdkBaseException> errorHandler =
                resolveErrorResponseHandler(executionParams, responseAdapter,
                                            executionContext.executionAttributes());

        return invoke(marshalled, requestProvider, executionParams.getRequestConfig(), executionContext,
                      responseHandler, errorHandler)
                .handle((resp, err) -> {
                    try {
                        if (err != null) {
                            throw Throwables.failure(err);
                        }
                        return resp;
                    } catch (Exception e) {
                        throw e;
                    } finally {
                        endClientExecution(awsRequestMetrics, executionParams.getRequestConfig(), request, resp);
                    }
                });
    }

    @Override
    public void close() throws Exception {
        client.close();
    }

    /**
     * When an operation has a streaming input, the customer must supply an {@link AsyncRequestProvider} to
     * provide the request content in a non-blocking manner. This adapts that interface to the
     * {@link SdkHttpRequestProvider} which the HTTP client SPI expects.
     *
     * @param asyncRequestProvider Customer supplied request provider.
     * @return Request provider to send to the HTTP layer.
     */
    private SdkHttpRequestProvider adaptAsyncRequestProvider(AsyncRequestProvider asyncRequestProvider) {
        return new SdkHttpRequestProvider() {

            @Override
            public long contentLength() {
                return asyncRequestProvider.contentLength();
            }

            @Override
            public void subscribe(Subscriber<? super ByteBuffer> s) {
                asyncRequestProvider.subscribe(s);
            }

        };
    }

    /**
     * Error responses are never streaming so we always use {@link SyncResponseHandlerAdapter}.
     *
     * @param responseAdapter Adapter to convert an SdkHttpFullResponse to a legacy HttpResponse.
     * @return Async handler for error responses.
     */
    private SdkHttpResponseHandler<? extends SdkBaseException> resolveErrorResponseHandler(
            ClientExecutionParams<?, ?> executionParams,
            Function<SdkHttpFullResponse, HttpResponse> responseAdapter,
            ExecutionAttributes executionAttributes) {
        return new SyncResponseHandlerAdapter<>(executionParams.getErrorResponseHandler(), responseAdapter, executionAttributes);
    }

    /**
     * Resolve the async response handler. If this operation has a streaming output then the customer
     * must provide an {@link software.amazon.awssdk.async.AsyncResponseHandler} which will be adapted
     * by the client implementation to a {@link SdkHttpResponseHandler} (unmarshalling is done in this
     * adaption layer). If this operation does not have a streaming output we use {@link SyncResponseHandlerAdapter}
     * to buffer all contents into memory then call out to the sync response handler ({@link
     * software.amazon.awssdk.http.HttpResponseHandler}).
     */
    private <OutputT> SdkHttpResponseHandler<OutputT> resolveResponseHandler(
            ClientExecutionParams<?, OutputT> executionParams,
            Function<SdkHttpFullResponse, HttpResponse> responseAdapter,
            ExecutionAttributes executionAttributes) {
        return executionParams.getResponseHandler() != null ?
                new SyncResponseHandlerAdapter<>(executionParams.getResponseHandler(), responseAdapter, executionAttributes) :
                executionParams.getAsyncResponseHandler();
    }

    /**
     * Normal invoke with authentication. Credentials are required and may be overriden at the
     * request level.
     **/
    private <OutputT> CompletableFuture<OutputT> invoke(SdkHttpFullRequest request,
                                                        SdkHttpRequestProvider requestProvider,
                                                        RequestConfig requestConfig,
                                                        ExecutionContext executionContext,
                                                        SdkHttpResponseHandler<OutputT> responseHandler,
                                                        SdkHttpResponseHandler<? extends SdkBaseException> errorResponseHandler) {

        executionContext.setCredentialsProvider(CredentialUtils.getCredentialsProvider(
                requestConfig, asyncClientConfiguration.credentialsProvider()));

        return doInvoke(request, requestProvider, requestConfig,
                        executionContext, responseHandler, errorResponseHandler);
    }

    /**
     * Invoke the request using the http client. Assumes credentials (or lack thereof) have been
     * configured in the OldExecutionContext beforehand.
     **/
    private <OutputT> CompletableFuture<OutputT> doInvoke(
            SdkHttpFullRequest request,
            SdkHttpRequestProvider requestProvider,
            RequestConfig requestConfig,
            ExecutionContext executionContext,
            SdkHttpResponseHandler<OutputT> responseHandler,
            SdkHttpResponseHandler<? extends SdkBaseException> errorResponseHandler) {
        return client.requestExecutionBuilder()
                     .requestProvider(requestProvider)
                     .request(request)
                     .requestConfig(requestConfig)
                     .executionContext(executionContext)
                     .errorResponseHandler(errorResponseHandler)
                     .execute(responseHandler);
    }
}
