package com.boku.auth.http;

import com.boku.util.Joiner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Representation of `Authorization` header format used for Boku HTTP authentication.<br>
 * This class also supports parsing and serializing the header contents.<br>
 * <br>
 * Example header:
 *  <pre>Authorization: 2/HMAC_SHA256(H+SHA256(E)) partner-id=bob, key-id=1, timestamp=1403052141, signature=8fdb4d525fc781478380a8a3b67cb014efc18c3cce12e79d0aa774bc179ba73a</pre>
 */
public class AuthorizationHeader {

    /**
     * Name of the header used to send this data in the request.
     */
    public static final String REQUEST_HEADER = "Authorization";

    /**
     * Name of the header used to send this data in the response.<br>
     * We use a custom header, since the HTTP spec says `Authorization` only appears in requests.
     */
    public static final String RESPONSE_HEADER = "X-SignedResponse";

    private static final String
        PARAM_PARTNER_ID            = "partner-id",
        PARAM_KEY_ID                = "key-id",
        PARAM_SIGNED_HEADERS        = "signed-headers",
        PARAM_TIMESTAMP             = "timestamp",
        PARAM_SIGNATURE             = "signature",
        PARAM_REQUIRES_CANONICALIZE = "requires-canonicalize";

    private String scheme;
    private String partnerId;
    private String keyId;
    private List<String> signedHeaders = new ArrayList<>();
    private Long timestamp;
    private String signature;
    private Boolean requiresCanonicalize;

    /**
     * Signature scheme used to sign the message and generate this header, e.g. "2/HMAC_SHA256(H+SHA256(E))".
     *
     * @return The scheme string. Should not be null.
     */
    public String getScheme() {
        return this.scheme;
    }

    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    /**
     * The ID of the partner (usually merchant) who owns the key used to sign the message.
     *
     * @return The partner-id. Should not be null.
     */
    public String getPartnerId() {
        return this.partnerId;
    }

    public void setPartnerId(String partnerId) {
        this.partnerId = partnerId;
    }

    /**
     * The ID of the key used to sign the message.
     * @return The key-id. Should not be null.
     */
    public String getKeyId() {
        return this.keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * A list of HTTP headers that were included during the signing process.
     *
     * @return The list of unique header names for signing. Must not be null, but may be empty.
     */
    public List<String> getSignedHeaders() {
        return this.signedHeaders;
    }

    public void setSignedHeaders(List<String> signedHeaders) {
        this.signedHeaders = signedHeaders;
    }

    /**
     * The time the message was signed, as the number of seconds since the UTC unix epoch (1970/01/01).
     *
     * @return The timestamp. Should not be null.
     */
    public Long getTimestamp() {
        return this.timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * The calculated signature of the message that this header accompanies.
     *
     * @return The signature value. Should not be null.
     */
    public String getSignature() {
        return this.signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Set to true if the signature in this header is valid only for the canonical form of the message, which may not
     * be the same as the message formatted as actually received over the wire.
     *
     * @return The requires-canonicalize flag, or null if not set.
     */
    public Boolean getRequiresCanonicalize() {
        return this.requiresCanonicalize;
    }

    public void setRequiresCanonicalize(Boolean requiresCanonicalize) {
        this.requiresCanonicalize = requiresCanonicalize;
    }

    /**
     * Given the string value of an `Authorization` header received from a remote peer, parse it into an instance of
     * {@link AuthorizationHeader}.<br>
     * Other than checks required to actually extract values from the string, no validation of required values or valid
     * value ranges is done in this method.
     *
     * @param headerValue The string value of the header. May not be null.
     * @return A parsed {@link AuthorizationHeader} instance, which may or may not be valid. Does not return null.
     */
    public static AuthorizationHeader parse(String headerValue) {
        headerValue = trimToNull(headerValue);
        if (headerValue == null) {
            throw new IllegalArgumentException("cannot be empty");
        }

        AuthorizationHeader ah = new AuthorizationHeader();

        String[] schemeAndPairs = headerValue.split("\\s+", 2);
        if (schemeAndPairs.length != 2) {
            throw new IllegalArgumentException("format invalid");
        }
        ah.scheme = schemeAndPairs[0];

        for (String segment : schemeAndPairs[1].split("\\s*,\\s*")) {
            String[] kv = segment.split("=", 2);
            if (kv.length < 2 || trimToNull(kv[1]) == null) {
                continue;
            }
            if (PARAM_PARTNER_ID.equals(kv[0])) {
                ah.partnerId = kv[1];
            } else if (PARAM_KEY_ID.equals(kv[0])) {
                ah.keyId = kv[1];
            } else if (PARAM_SIGNED_HEADERS.equals(kv[0])) {
                ah.signedHeaders = new ArrayList<>();
                ah.signedHeaders.addAll(Arrays.asList(kv[1].split(";")));
            } else if (PARAM_TIMESTAMP.equals(kv[0])) {
                try {
                    ah.timestamp = Long.valueOf(kv[1]);
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("invalid timestamp, " + kv[1]);
                }
            } else if (PARAM_SIGNATURE.equals(kv[0])) {
                ah.signature = kv[1];
            } else if (PARAM_REQUIRES_CANONICALIZE.equals(kv[0])) {
                ah.requiresCanonicalize = Boolean.parseBoolean(kv[1]);
            }
        }

        return ah;
    }

    /**
     * Alias for {@link #parse}.
     *
     * @param headerValue The string value of the header. May not be null.
     * @return A parsed {@link AuthorizationHeader} instance, which may or may not be valid. Does not return null.
     */
    public static AuthorizationHeader valueOf(String headerValue) {
        return parse(headerValue);
    }

    /**
     * Serialize this AuthorizationHeader into its textual representation for transmission in the `Authorization`
     * header, and parsable by the {@link #parse} method.
     */
    @Override
    public String toString() {
        ToStringer ts = new ToStringer(this.scheme);

        ts.append(PARAM_PARTNER_ID, this.partnerId);
        ts.append(PARAM_KEY_ID, this.keyId);

        if (!this.signedHeaders.isEmpty()) {
            Joiner.join(ts.key(PARAM_SIGNED_HEADERS), ";", this.signedHeaders);
        }

        ts.append(PARAM_TIMESTAMP, this.timestamp);
        ts.append(PARAM_SIGNATURE, this.signature);

        if (this.requiresCanonicalize != null) {
            ts.append(PARAM_REQUIRES_CANONICALIZE, this.requiresCanonicalize);
        }

        return ts.toString();
    }


    private static class ToStringer {

        final StringBuilder sb;
        int numParams = 0;

        ToStringer(String scheme) {
            sb = new StringBuilder().append(scheme);
        }

        ToStringer append(String key, Object value) {
            key(key).append(value);
            return this;
        }

        StringBuilder key(String key) {
            if (numParams++ == 0) {
                sb.append(' ');
            } else {
                sb.append(", ");
            }
            sb.append(key).append('=');
            return sb;
        }

        public String toString() {
            return sb.toString();
        }
    }

    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        s = s.trim();
        return s.length() == 0 ? null : s;
    }
}
