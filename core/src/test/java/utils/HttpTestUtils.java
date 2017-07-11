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

package utils;

import software.amazon.awssdk.config.ClientOverrideConfiguration;
import software.amazon.awssdk.config.MutableClientConfiguration;
import software.amazon.awssdk.config.defaults.GlobalClientConfigurationDefaults;
import software.amazon.awssdk.http.AmazonHttpClient;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.loader.DefaultSdkHttpClientFactory;
import software.amazon.awssdk.internal.http.timers.TimeoutTestConstants;
import software.amazon.awssdk.retry.PredefinedRetryPolicies;
import software.amazon.awssdk.retry.RetryPolicy;
import software.amazon.awssdk.retry.RetryPolicyAdapter;
import software.amazon.awssdk.utils.AttributeMap;

public class HttpTestUtils {
    public static SdkHttpClient testSdkHttpClient() {
        return new DefaultSdkHttpClientFactory().createHttpClientWithDefaults(
                AttributeMap.empty().merge(SdkHttpConfigurationOption.GLOBAL_HTTP_DEFAULTS));
    }

    public static AmazonHttpClient testAmazonHttpClient() {
        return testClientBuilder().httpClient(testSdkHttpClient()).build();
    }

    public static TestClientBuilder testClientBuilder() {
        return new TestClientBuilder();
    }

    public static class TestClientBuilder {
        private RetryPolicy retryPolicy;
        private SdkHttpClient httpClient;

        public TestClientBuilder retryPolicy(RetryPolicy retryPolicy) {
            this.retryPolicy = retryPolicy;
            return this;
        }

        public TestClientBuilder httpClient(SdkHttpClient sdkHttpClient) {
            this.httpClient = sdkHttpClient;
            return this;
        }

        public AmazonHttpClient build() {
            SdkHttpClient sdkHttpClient = this.httpClient != null ? this.httpClient : testSdkHttpClient();
            ClientOverrideConfiguration overrideConfiguration =
                    ClientOverrideConfiguration.builder()
                                               .totalExecutionTimeout(TimeoutTestConstants.CLIENT_EXECUTION_TIMEOUT)
                                               .apply(this::configureRetryPolicy)
                                               .build();

            MutableClientConfiguration clientConfig = new MutableClientConfiguration()
                    .httpClient(sdkHttpClient)
                    .overrideConfiguration(overrideConfiguration);

            new GlobalClientConfigurationDefaults().applySyncDefaults(clientConfig);

            return AmazonHttpClient.builder().syncClientConfiguration(clientConfig).build();
        }

        private ClientOverrideConfiguration.Builder configureRetryPolicy(ClientOverrideConfiguration.Builder builder) {
            if (retryPolicy != null) {
                builder.retryPolicy(new RetryPolicyAdapter(retryPolicy));
            }
            return builder;
        }
    }
}
