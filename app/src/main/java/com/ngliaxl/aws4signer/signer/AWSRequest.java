package com.ngliaxl.aws4signer.signer;

import java.util.HashMap;
import java.util.Map;

public class AWSRequest {

    private final Map<String, String> headers = new HashMap<>();

    private okhttp3.Request request;


    public AWSRequest(okhttp3.Request request) {
        this.request = request;
    }


    public okhttp3.Request get() {
        return request;
    }

    public void addHeader(String name, String value) {
        headers.put(name, value);
    }

    public Map<String, String> getHeaders() {
        return headers;
    }
}
