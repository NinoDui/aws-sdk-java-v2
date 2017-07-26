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

package software.amazon.awssdk.services.s3.handlers;

import static software.amazon.awssdk.utils.FunctionalUtils.invokeSafely;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import software.amazon.awssdk.SdkRequest;
import software.amazon.awssdk.annotation.ReviewBeforeRelease;
import software.amazon.awssdk.http.HttpStatusCodes;
import software.amazon.awssdk.http.SdkHttpFullResponse;
import software.amazon.awssdk.interceptor.ExecutionAttributes;
import software.amazon.awssdk.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.interceptor.context.BeforeUnmarshallingContext;
import software.amazon.awssdk.services.s3.model.GetBucketLocationRequest;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyRequest;
import software.amazon.awssdk.util.SdkHttpUtils;
import software.amazon.awssdk.utils.IoUtils;

/**
 * Enables S3 single-string responses to be correctly unmarshalled.
 *
 * Most S3 operations return a structure wrapped in an outer XML element with two exceptions
 *
 * <ul>
 *  <li>GetBucketLocation which returns {@code <LocationConstraint>region</LocationConstraint> } </li>
 *  <li>GetBucketPolicy which returns a raw JSON document representing the policy</li>
 * </ul>
 * The Sax unmarshaller used for S3 is expecting this outer wrapper. This response handler modifies the
 * responses of these operations to include the required XML wrappers.
 */
public final class SingleStringExecutionInterceptor implements ExecutionInterceptor {

    @Override
    @ReviewBeforeRelease("Change to use instanceof on request object after request handlers refactor")
    public SdkHttpFullResponse modifyHttpResponse(BeforeUnmarshallingContext execution, ExecutionAttributes executionAttributes) {
        // Only modify successful responses
        if (execution.httpResponse().getStatusCode() / 100 != HttpStatusCodes.OK / 100) {
            return execution.httpResponse();
        }

        SdkRequest request = execution.request();
        if (request instanceof GetBucketPolicyRequest) {
            return updateGetBucketPolicyResponse(execution.httpResponse());
        } else if (request instanceof GetBucketLocationRequest) {
            return updateGetBucketLocationRequest(execution.httpResponse());
        }
        return execution.httpResponse();
    }

    private SdkHttpFullResponse updateGetBucketPolicyResponse(SdkHttpFullResponse httpResponse) {
        List<InputStream> streams = Arrays.asList(
            new ByteArrayInputStream("<Policy>".getBytes(StandardCharsets.UTF_8)),
            httpResponse.getContent(),
            new ByteArrayInputStream("</Policy>".getBytes(StandardCharsets.UTF_8))
        );
        return httpResponse.modify(b -> b.content(new SequenceInputStream(Collections.enumeration(streams))));
    }

    private SdkHttpFullResponse updateGetBucketLocationRequest(SdkHttpFullResponse httpResponse) {
        String contents = invokeSafely(() -> IoUtils.toString(httpResponse.getContent()));
        String newContents = contents.replace("<LocationConstraint", "<Wrap><LocationConstraint")
                                     .replace("</LocationConstraint>", "</LocationConstraint></Wrap>");
        return httpResponse.modify(b -> b.content(new ByteArrayInputStream(newContents.getBytes(StandardCharsets.UTF_8))));
    }
}
