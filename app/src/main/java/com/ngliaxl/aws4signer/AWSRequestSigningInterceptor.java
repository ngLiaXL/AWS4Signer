/*
 *    Copyright (C) 2016 Amit Shekhar
 *    Copyright (C) 2011 Android Open Source Project
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.ngliaxl.aws4signer;


import com.ngliaxl.aws4signer.signer.AWS4Signer;
import com.ngliaxl.aws4signer.signer.AWSCredentials;
import com.ngliaxl.aws4signer.signer.AWSRequest;

import java.io.IOException;
import java.util.Map;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;


public class AWSRequestSigningInterceptor implements Interceptor {

    private AWS4Signer signer;
    private AWSCredentials awsCredentials;

    public AWSRequestSigningInterceptor(AWSCredentials basicAWSCredentials) {
        signer = new AWS4Signer("execute-api", "cn-north-1");
        this.awsCredentials = basicAWSCredentials;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();

        AWSRequest awsRequest = new AWSRequest(request);
        signer.sign(awsRequest, awsCredentials);

        Request.Builder builder = request.newBuilder();
        for (Map.Entry<String, String> stringStringEntry : awsRequest.getHeaders().entrySet()) {
            builder.addHeader(stringStringEntry.getKey(), stringStringEntry.getValue());
        }
        return chain.proceed(builder.build());
    }


}

