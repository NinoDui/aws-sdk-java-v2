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

package software.amazon.awssdk.http;

import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.time.Duration;
import org.apache.http.HttpHost;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.protocol.HttpContext;
import org.junit.Assert;
import org.junit.Test;
import software.amazon.awssdk.AmazonClientException;
import software.amazon.awssdk.LegacyClientConfiguration;
import software.amazon.awssdk.http.apache.ApacheSdkHttpClientFactory;
import software.amazon.awssdk.internal.http.request.EmptyHttpRequest;

/**
 * This test is to verify that the apache-httpclient library has fixed the bug where socket timeout configuration is
 * incorrectly ignored during SSL handshake. This test is expected to hang (and fail after the junit timeout) if run
 * against the problematic httpclient version (e.g. 4.3).
 *
 * @link https://issues.apache.org/jira/browse/HTTPCLIENT-1478
 */
public class AmazonHttpClientSslHandshakeTimeoutIntegrationTest extends UnresponsiveMockServerTestBase {

    private static final Duration CLIENT_SOCKET_TO = Duration.ofSeconds(1);

    @Test(timeout = 60 * 1000)
    public void testSslHandshakeTimeout() {
        AmazonHttpClient httpClient = AmazonHttpClient.builder()
                                                      .sdkHttpClient(ApacheSdkHttpClientFactory.builder()
                                                                                               .socketTimeout(CLIENT_SOCKET_TO)
                                                                                               .build()
                                                                                               .createHttpClient())
                                                      .clientConfiguration(new LegacyClientConfiguration().withMaxErrorRetry(0))
                                                      .build();

        System.out.println("Sending request to localhost...");

        try {
            httpClient.requestExecutionBuilder()
                      .request(new EmptyHttpRequest(server.getHttpsEndpoint(), HttpMethodName.GET))
                      .execute();
            fail("Client-side socket read timeout is expected!");

        } catch (AmazonClientException e) {
            /**
             * Http client catches the SocketTimeoutException and throws a
             * ConnectTimeoutException.
             * {@link DefaultHttpClientConnectionOperator#connect(ManagedHttpClientConnection, HttpHost,
             * InetSocketAddress, int, SocketConfig, HttpContext)}
             */
            Assert.assertTrue(e.getCause() instanceof ConnectTimeoutException);

            ConnectTimeoutException cte = (ConnectTimeoutException) e.getCause();
            Assert.assertThat(cte.getMessage(), org.hamcrest.Matchers
                    .containsString("Read timed out"));
        }
    }
}
