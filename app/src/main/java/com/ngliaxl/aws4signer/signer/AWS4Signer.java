package com.ngliaxl.aws4signer.signer;


import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import okhttp3.Request;
import okhttp3.RequestBody;
import okio.Buffer;

import static com.ngliaxl.aws4signer.signer.AWSV4Utils.UTF8;

/**
 * https://docs.aws.amazon.com/zh_cn/general/latest/gr/sigv4_signing.html
 *
 * AWS4Signer for okHttp
 */
public class AWS4Signer {

    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String TERMINATOR = "aws4_request";
    private static final String DATE_PATTERN = "yyyyMMdd";
    private static final String TIME_PATTERN = "yyyyMMdd'T'HHmmss'Z'";


    private String serviceName;
    private String regionName;


    public AWS4Signer(String serviceName, String regionName) {
        this.serviceName = serviceName;
        this.regionName = regionName;
    }


    public void sign(AWSRequest request, AWSCredentials credentials) {
        final AWSCredentials sanitizedCredentials = sanitizeCredentials(credentials);

        addHostHeader(request);
        final long dateMilli = System.currentTimeMillis();

        final String dateStamp = getDateStamp(dateMilli);
        final String scope = getScope(dateStamp);

        final String contentSha256 = calculateContentHash(request.get());

        final String timeStamp = getTimeStamp(dateMilli);
        request.addHeader("X-Amz-Date", timeStamp);

        final String signingCredentials = sanitizedCredentials.getAWSAccessKeyId() + "/" + scope;

        final HeaderSigningResult headerSigningResult = computeSignature(
                request,
                dateStamp,
                timeStamp,
                ALGORITHM,
                contentSha256,
                sanitizedCredentials);

        final String credentialsAuthorizationHeader =
                "Credential=" + signingCredentials;
        final String signedHeadersAuthorizationHeader =
                "SignedHeaders=" + getSignedHeadersString(request);
        final String signatureAuthorizationHeader =
                "Signature=" + AWSV4Utils.toHex(headerSigningResult.getSignature());

        final String authorizationHeader = ALGORITHM + " "
                + credentialsAuthorizationHeader + ", "
                + signedHeadersAuthorizationHeader + ", "
                + signatureAuthorizationHeader;
        request.addHeader("Authorization", authorizationHeader);

    }

    private String getSignedHeadersString(AWSRequest request) {
        final List<String> sortedHeaders = new ArrayList<>();
        sortedHeaders.addAll(request.getHeaders().keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);

        final StringBuilder buffer = new StringBuilder();
        for (final String header : sortedHeaders) {
            if (needsSign(header)) {
                if (buffer.length() > 0) {
                    buffer.append(";");
                }
                buffer.append(AWSV4Utils.lowerCase(header));
            }
        }

        return buffer.toString();
    }


    private void addHostHeader(AWSRequest request) {
        // AWS4 requires that we sign the Host header so we
        // have to have it in the request by the time we sign.
        String hostHeader = request.get().url().host();
        request.addHeader("Host", hostHeader);
    }


    private String calculateContentHash(Request request) {
        RequestBody body = request.body();
        String contentSha256 = "";
        if (body != null) {
            Buffer buffer = new Buffer();
            try {
                RequestBody requestBody = request.newBuilder().build().body();
                if (requestBody != null) {
                    requestBody.writeTo(buffer);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            contentSha256 = buffer.readUtf8();
        }
        return AWSV4Utils.toHex(hash(contentSha256));
    }

    /**
     * Determine if a header needs to be signed. The headers must be signed
     * according to sigv4 spec are host, date, Content-MD5and all x-amz headers.
     *
     * @param header header key
     * @return true if it should be sign, false otherwise
     */
    private boolean needsSign(String header) {
        return "date".equalsIgnoreCase(header) || "Content-MD5".equalsIgnoreCase(header)
                || "host".equalsIgnoreCase(header)
                || header.startsWith("x-amz") || header.startsWith("X-Amz");
    }

    private AWSCredentials sanitizeCredentials(AWSCredentials credentials) {
        String accessKeyId;
        String secretKey;
        synchronized (credentials) {
            accessKeyId = credentials.getAWSAccessKeyId();
            secretKey = credentials.getAWSSecretKey();
        }
        if (secretKey != null) {
            secretKey = secretKey.trim();
        }
        if (accessKeyId != null) {
            accessKeyId = accessKeyId.trim();
        }
        return new BasicAWSCredentials(accessKeyId, secretKey);
    }


    private String getScope(String dateStamp) {
        return dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;
    }

    private String getDateStamp(long dateMilli) {
        DateFormat dateFormat = new SimpleDateFormat(DATE_PATTERN, Locale.getDefault());
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormat.format(new Date(dateMilli));
    }

    private String getTimeStamp(long dateMilli) {
        DateFormat dateFormat = new SimpleDateFormat(TIME_PATTERN, Locale.getDefault());
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormat.format(new Date(dateMilli));
    }


    private HeaderSigningResult computeSignature(
            AWSRequest request,
            String dateStamp,
            String timeStamp,
            String algorithm,
            String contentSha256,
            AWSCredentials sanitizedCredentials) {

        final String scope = dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;
        //AWS4-HMAC-SHA256
        //20200103T052641Z
        //20200103/cn-north-1/execute-api/aws4_request
        //6a74134e0d8dd4634e58cd28d6d4a7f74d78e4bad559d6ea27c921b44d95f901
        final String stringToSign = getStringToSign(algorithm, timeStamp, scope,
                getCanonicalRequest(request, contentSha256));

        // AWS4 uses a series of derived keys, formed by hashing different
        // pieces of data
        final byte[] kSecret = ("AWS4" + sanitizedCredentials.getAWSSecretKey())
                .getBytes(UTF8);
        final byte[] kDate = sign(dateStamp, kSecret, SigningAlgorithm.HmacSHA256);
        final byte[] kRegion = sign(regionName, kDate, SigningAlgorithm.HmacSHA256);
        final byte[] kService = sign(serviceName, kRegion, SigningAlgorithm.HmacSHA256);
        final byte[] kSigning = sign(TERMINATOR, kService, SigningAlgorithm.HmacSHA256);

        final byte[] signature = sign(stringToSign.getBytes(UTF8), kSigning,
                SigningAlgorithm.HmacSHA256);
        return new HeaderSigningResult(timeStamp, scope, kSigning, signature);
    }

    protected String getCanonicalRequest(AWSRequest request, String contentSha256) {
        /* This would url-encode the resource path for the first time */
        final String path = request.get().url().encodedPath();

        final String canonicalRequest =
                request.get().method() + "\n" +

                        // /sit/api/safetyScreen/informationScreen/112
                        getCanonicalizedResourcePath(path) + "\n" +
                        getCanonicalizedQueryString(request.get()) + "\n" +
                        // host:0z439arge6.execute-api.cn-north-1.amazonaws.com.cn
                        //x-amz-date:20200103T055215Z
                        getCanonicalizedHeaderString(request) + "\n" +
                        // host;x-amz-date
                        getSignedHeadersString(request) + "\n" +
                        contentSha256;
        return canonicalRequest;
    }

    private String getCanonicalizedQueryString(Request request) {
        Set<String> names = request.url().queryParameterNames();
        final StringBuilder builder = new StringBuilder();

        Iterator<String> namePairs = names.iterator();
        while (namePairs.hasNext()){
            String name = namePairs.next();
            Iterator<String> valuePairs = request.url().queryParameterValues(name).iterator();
            while (valuePairs.hasNext()) {
                builder.append(AWSV4Utils.urlEncode(name, false));
                builder.append("=");
                builder.append(AWSV4Utils.urlEncode(valuePairs.next(), false));
                if (valuePairs.hasNext()) {
                    builder.append("&");
                }
            }
            if (namePairs.hasNext()) {
                builder.append("&");
            }
        }

        return builder.toString();
    }

    protected String getCanonicalizedResourcePath(String resourcePath) {
        if (resourcePath == null || resourcePath.length() == 0) {
            return "/";
        } else {
            if (resourcePath.startsWith("/")) {
                return resourcePath;
            } else {
                return "/".concat(resourcePath);
            }
        }
    }


    protected String getCanonicalizedHeaderString(AWSRequest request) {
        final List<String> sortedHeaders = new ArrayList<>();
        sortedHeaders.addAll(request.getHeaders().keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);

        final StringBuilder buffer = new StringBuilder();
        for (final String name : sortedHeaders) {
            if (needsSign(name)) {
                final String key = AWSV4Utils.lowerCase(name).replaceAll("\\s+", " ");
                final String value = request.getHeaders().get(name);

                buffer.append(key).append(":");
                if (value != null) {
                    buffer.append(value.replaceAll("\\s+", " "));
                }

                buffer.append("\n");
            }
        }

        return buffer.toString();
    }


    protected String getStringToSign(String algorithm, String dateTime, String scope,
                                     String canonicalRequest) {
        final String stringToSign =
                algorithm + "\n" +
                        dateTime + "\n" +
                        scope + "\n" +
                        AWSV4Utils.toHex(hash(canonicalRequest));
        return stringToSign;
    }

    public byte[] hash(String text) {
        return AWSV4Utils.doHash(text);
    }

    /**
     * Signs using the given signing algorithm.
     *
     * @param stringData the data.
     * @param key        the key in bytes.
     * @param algorithm  the signing algorithm.
     * @return signed result in bytes.
     */
    private byte[] sign(String stringData, byte[] key, SigningAlgorithm algorithm) {
        try {
            final byte[] data = stringData.getBytes(UTF8);
            return sign(data, key, algorithm);
        } catch (final Exception e) {
            throw new RuntimeException("Unable to calculate a request signature: "
                    + e.getMessage(), e);
        }
    }

    private byte[] sign(byte[] data, byte[] key, SigningAlgorithm algorithm) {
        try {
            final Mac mac = Mac.getInstance(algorithm.toString());
            mac.init(new SecretKeySpec(key, algorithm.toString()));
            return mac.doFinal(data);
        } catch (final Exception e) {
            throw new RuntimeException("Unable to calculate a request signature: "
                    + e.getMessage(), e);
        }
    }


    protected static class HeaderSigningResult {

        private final String dateTime;
        private final String scope;
        private final byte[] kSigning;
        private final byte[] signature;

        public HeaderSigningResult(String dateTime, String scope, byte[] kSigning, byte[] signature) {
            this.dateTime = dateTime;
            this.scope = scope;
            this.kSigning = kSigning;
            this.signature = signature;
        }

        public String getDateTime() {
            return dateTime;
        }

        public String getScope() {
            return scope;
        }

        public byte[] getKSigning() {
            final byte[] kSigningCopy = new byte[kSigning.length];
            System.arraycopy(kSigning, 0, kSigningCopy, 0, kSigning.length);
            return kSigningCopy;
        }

        public byte[] getSignature() {
            final byte[] signatureCopy = new byte[signature.length];
            System.arraycopy(signature, 0, signatureCopy, 0, signature.length);
            return signatureCopy;
        }
    }
}
