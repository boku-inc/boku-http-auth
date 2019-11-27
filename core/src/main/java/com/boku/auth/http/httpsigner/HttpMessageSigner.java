package com.boku.auth.http.httpsigner;

import java.security.InvalidKeyException;

import com.boku.auth.http.exception.AuthorizationException;
import com.boku.auth.http.exception.AuthorizationFailedException;
import com.boku.auth.http.exception.InvalidApplicationSuppliedAuthorizationHeaderException;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.httpmessage.CanonicalHttpMessage;
import com.boku.auth.http.stringsigner.SignatureAlgorithm;
import com.boku.auth.http.stringsigner.StringSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.boku.auth.http.AuthorizationHeader;

/**
 * Signs HTTP requests and responses.
 */
public class HttpMessageSigner {

    private static final Logger logger = LoggerFactory.getLogger(HttpMessageSigner.class);

    // Format is $version/$description. Version is reserved for major changes not expressible in description.
    // We only support one at the moment.
    public static final String SCHEME = "2/HMAC_SHA256(H+SHA256(E))";

    private final StringSigner stringSigner;

    /**
     * Construct a new instance that uses the given {@link StringSigner} to generate signatures.
     */
    public HttpMessageSigner(StringSigner ss) {
        this.stringSigner = ss;
    }

    /**
     * Given a partially specified {@link AuthorizationHeader} (only partnerId and keyId are required), and a
     * {@link CanonicalHttpMessage} to sign, generate the signature and place it into the given authHeader.
     *
     * @param authHeader The {@link AuthorizationHeader} instance to populate.
     * @param httpMessage A {@link CanonicalHttpMessage} instance
     * @throws InvalidApplicationSuppliedAuthorizationHeaderException If the given authHeader did not specify a known key, or some other configuration error occurred.
     */
    public void sign(AuthorizationHeader authHeader, CanonicalHttpMessage httpMessage) {
        if (authHeader.getScheme() == null) {
            authHeader.setScheme(SCHEME);
        }
        if (authHeader.getTimestamp() == null) {
            authHeader.setTimestamp(System.currentTimeMillis() / 1000);
        }
        String signature;
        try {
            signature = this.generateSignature(authHeader, httpMessage);
        } catch (InvalidAuthorizationHeaderException ex) {
            throw new InvalidApplicationSuppliedAuthorizationHeaderException("Failed to sign message", ex);
        }
        authHeader.setSignature(signature);
    }

    /**
     * Given a {@link CanonicalHttpMessage} and an {@link AuthorizationHeader} pre-filled out with a signature,
     * recalculate the signature (as in {@link #sign}), and verify it matches the
     * {@link AuthorizationHeader#getSignature() signature} provided in the AuthorizationHeader.
     *
     * @param authHeader A fully populated AuthorizationHeader pertaining to the given httpMessage.
     * @param httpMessage The HTTP request or response for which to check the signature.
     * @throws AuthorizationException If the signature was incorrect, or the supplied AuthorizationHeader was invalid in any other way.
     */
    public void verifySignature(AuthorizationHeader authHeader, CanonicalHttpMessage httpMessage) throws AuthorizationException {
        String sig = this.generateSignature(authHeader, httpMessage);
        if (!sig.equals(authHeader.getSignature())) {
            logger.warn("Verification failed - expected signature {} in auth header: {}", sig, authHeader);
            throw new AuthorizationFailedException("Invalid signature");
        }
        logger.debug("Verified signature correct for auth header: {}", authHeader);
    }

    /**
     * Note: you should usually not need to call this method directly.
     * Prefer {@link #sign} or {@link #verifySignature} instead.<br>
     * <br>
     * Calculate a signature based on the information provided and return it. The given argument data structures are not
     * modified.
     *
     * @param authHeader An AuthorizationHeader, fully specified other than {@link AuthorizationHeader#getSignature() signature} which may be missing.
     * @param httpMessage The HTTP request or response to be signed.
     * @return The hex encoded signature. Does not return null.
     * @throws InvalidAuthorizationHeaderException If the given authHeader contained unrecognized signing parameters, e.g. unknown key ID.
     */
    public String generateSignature(AuthorizationHeader authHeader, CanonicalHttpMessage httpMessage) throws InvalidAuthorizationHeaderException {
        if (!SCHEME.equals(authHeader.getScheme())) {
            logger.warn("Unknown scheme in auth header: {}", authHeader);
            throw new InvalidAuthorizationHeaderException("Unknown authorization scheme, " + authHeader.getScheme());
        }

        String stringToSign = httpMessage.toString(new StringBuilder())
            .append(authHeader.getTimestamp())
            .toString();

        String hmac;
        try {
            hmac = this.stringSigner.generateSignature(
                    SignatureAlgorithm.HMAC_SHA256,
                    authHeader.getPartnerId(),
                    authHeader.getKeyId(),
                    stringToSign
            );
        } catch (InvalidKeyException ex) {
            logger.warn("Invalid partner-id / key-id in auth header? {}", authHeader, ex);
            throw new InvalidAuthorizationHeaderException("Unrecognized partner-id or key-id");
        }

        logger.debug("Generated signature {} using key-id {} for {}:\n{}",
                hmac, authHeader.getKeyId(), httpMessage.getClass().getSimpleName(), stringToSign
        );
        return hmac;
    }

}
