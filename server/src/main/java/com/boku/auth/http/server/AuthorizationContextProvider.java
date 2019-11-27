package com.boku.auth.http.server;

import java.util.List;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.AuthorizationHeaderValidator;
import com.boku.auth.http.exception.AuthorizationException;
import com.boku.auth.http.exception.AuthorizationFailedException;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.util.Joiner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.boku.auth.http.server.spi.CurrentRequestAuthInfo;
import com.boku.auth.http.server.spi.CurrentRequestAuthInfoFactory;

/**
 * Framework independent class to verify and return the current {@link AuthorizationContext}, given that we've been
 * provided a webserver-implementation-specific factory that can provide current request information.
 */
public class AuthorizationContextProvider {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationContextProvider.class);

    public static final long TIMESTAMP_VALIDITY_PERIOD_SECONDS = 300;

    private final CurrentRequestAuthInfoFactory currentRequestInfoFactory;
    private final HttpMessageSigner httpMessageSigner;

    /**
     * @param currentRequestAuthInfoFactory Framework specific factory implementation to get hold of {@link CurrentRequestAuthInfo} for verification
     * @param httpMessageSigner A {@link HttpMessageSigner}, used for verifying the signature
     */
    public AuthorizationContextProvider(CurrentRequestAuthInfoFactory currentRequestAuthInfoFactory,
            HttpMessageSigner httpMessageSigner) {
        this.currentRequestInfoFactory = currentRequestAuthInfoFactory;
        this.httpMessageSigner = httpMessageSigner;
    }

    /**
     * Get the current {@link AuthorizationContext}.<br>
     * The returned context has been verified to ensure that the request itself was correctly signed by the
     * partner-owned key identified in the supplied {@link AuthorizationHeader}.<br>
     * By this point, <b>no</b> verification has been performed as to whether the signing partner is authorized to
     * access any entities referenced within the request body itself.
     *
     * @return An {@link AuthorizationContext}. Does not return null.
     * @throws AuthorizationException If the Authorization header is invalid or not supplied by the client.
     */
    public AuthorizationContext get() throws AuthorizationException {
        CurrentRequestAuthInfo requestInfo = this.currentRequestInfoFactory.getCurrentRequestInfo();

        CanonicalHttpRequest canonicalRequest = requestInfo.getCanonicalRequest();

        logger.debug("Providing AuthorizationContext for {} {}...", canonicalRequest.getMethod(), canonicalRequest.getPath());

        AuthorizationHeader authHeader = requestInfo.getAuthorizationHeader();
        logger.debug("    Got auth header: {} ", authHeader);
        List<String> validationErrors = AuthorizationHeaderValidator.getErrors(authHeader);
        if (!validationErrors.isEmpty()) {
            throw new InvalidAuthorizationHeaderException("Invalid Authorization header: "
                    + Joiner.join("; ", validationErrors));
        }

        logger.debug("    Got canonical request: {}", canonicalRequest);

        long now = System.currentTimeMillis() / 1000;
        if (Math.abs(now - authHeader.getTimestamp()) > TIMESTAMP_VALIDITY_PERIOD_SECONDS) {
            logger.warn("Authorization header timestamp too old: {}", authHeader);
            throw new AuthorizationFailedException("Signature expired");
        }

        this.httpMessageSigner.verifySignature(authHeader, canonicalRequest);

        logger.debug("    Authorization header signature verified, returning auth context...");

        return new AuthorizationContext(authHeader);
    }

}
