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

import software.amazon.awssdk.AmazonClientException;

/**
 * An exception raised in the context of an execution interceptor. This exception will abort the request to the service and
 * be returned or thrown as a result of the client invocation.
 */
public class ExecutionInterceptorException extends AmazonClientException {
    public ExecutionInterceptorException(String message, Throwable t) {
        super(message, t);
    }

    public ExecutionInterceptorException(String message) {
        super(message);
    }

    public ExecutionInterceptorException(Throwable t) {
        super(t);
    }
}
