package com.ngliaxl.aws4signer.signer;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class AWSV4Utils {


    private static final ThreadLocal<MessageDigest> SHA256_MESSAGE_DIGEST;
    private static final String DEFAULT_ENCODING = "UTF-8";
    private static final Pattern ENCODED_CHARACTERS_PATTERN;

    public static final Charset UTF8 = Charset.forName(DEFAULT_ENCODING);


    static {
        final StringBuilder pattern = new StringBuilder();

        pattern
                .append(Pattern.quote("+"))
                .append("|")
                .append(Pattern.quote("*"))
                .append("|")
                .append(Pattern.quote("%7E"))
                .append("|")
                .append(Pattern.quote("%2F"));

        ENCODED_CHARACTERS_PATTERN = Pattern.compile(pattern.toString());
    }

    static {
        SHA256_MESSAGE_DIGEST = new ThreadLocal<MessageDigest>() {
            @Override
            protected MessageDigest initialValue() {
                try {
                    return MessageDigest.getInstance("SHA-256");
                } catch (final NoSuchAlgorithmException e) {
                    throw new RuntimeException(
                            "Unable to get SHA256 Function"
                                    + e.getMessage(),
                            e);
                }
            }
        };
    }


    /**
     * Converts a string to lower case with Locale.ENGLISH.
     *
     * @param str the string to lower case
     * @return the lower case of the string, or null if the string is null
     */
    public static String lowerCase(String str) {
        if (str == null) {
            return null;
        } else if (str.isEmpty()) {
            return "";
        } else {
            return str.toLowerCase(Locale.ENGLISH);
        }
    }


    private static final int HEX_LENGTH_8 = 8;
    private static final int HEX_PARSE_16 = 16;
    private static final int FF_LOCATION = 6;


    public static String toHex(byte[] data) {
        final StringBuilder sb = new StringBuilder(data.length * 2);
        for (int i = 0; i < data.length; i++) {
            String hex = Integer.toHexString(data[i]);
            if (hex.length() == 1) {
                // Append leading zero.
                sb.append("0");
            } else if (hex.length() == HEX_LENGTH_8) {
                // Remove ff prefix from negative numbers.
                hex = hex.substring(FF_LOCATION);
            }
            sb.append(hex);
        }
        return lowerCase(sb.toString());
    }


    public static byte[] doHash(String text) {
        try {
            final MessageDigest md = getMessageDigestInstance();
            md.update(text.getBytes(UTF8));
            return md.digest();
        } catch (final Exception e) {
            throw new RuntimeException(
                    "Unable to compute hash while signing request: "
                            + e.getMessage(),
                    e);
        }
    }

    private static MessageDigest getMessageDigestInstance() {
        final MessageDigest messageDigest = SHA256_MESSAGE_DIGEST.get();
        messageDigest.reset();
        return messageDigest;
    }

    public static String urlEncode(final String value, final boolean path) {
        if (value == null) {
            return "";
        }

        try {
            final String encoded = URLEncoder.encode(value, DEFAULT_ENCODING);

            final Matcher matcher = ENCODED_CHARACTERS_PATTERN.matcher(encoded);
            final StringBuffer buffer = new StringBuffer(encoded.length());

            while (matcher.find()) {
                String replacement = matcher.group(0);

                if ("+".equals(replacement)) {
                    replacement = "%20";
                } else if ("*".equals(replacement)) {
                    replacement = "%2A";
                } else if ("%7E".equals(replacement)) {
                    replacement = "~";
                } else if (path && "%2F".equals(replacement)) {
                    replacement = "/";
                }
                matcher.appendReplacement(buffer, replacement);
            }

            matcher.appendTail(buffer);
            return buffer.toString();

        } catch (final UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }


}
