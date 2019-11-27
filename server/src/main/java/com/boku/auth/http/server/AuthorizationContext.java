package com.boku.auth.http.server;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.AuthorizationFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The authorization context within which the current request is operating.<br>
 * This is derived from the Authorization header supplied by the client, which you can assume has been pre-verified by
 * the time you get hold of an instance of this class.
 */
public class AuthorizationContext {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationContext.class);

    private final AuthorizationHeader authorizationHeader;

    public AuthorizationContext(AuthorizationHeader ah) {
        if (ah.getPartnerId() == null) {
            throw new IllegalStateException("AuthorizationHeader.partnerId is null");
        }
        this.authorizationHeader = ah;
    }

    /**
     * The original {@link AuthorizationHeader} instance supplied with the request.
     */
    public AuthorizationHeader getAuthorizationHeader() {
        return this.authorizationHeader;
    }

    /**
     * Convenience method to check the given partnerId against the partner identified in the
     * {@link #getAuthorizationHeader() authorization header}, and throw an authorization exception if they don't
     * match. This is needed in cases where the partner ID appears in the application-level request, and you want to
     * make sure one valid partner is not posing as another.<br>
     *
     * @param partnerId The partner ID called out in the request body
     * @throws AuthorizationFailedException if the auth header refers to an unexpected partner
     */
    public void assertValidForPartner(String partnerId) throws AuthorizationFailedException {
        if (!this.authorizationHeader.getPartnerId().equals(partnerId)) {
            logger.warn("Authorization header not valid for partner '{}': {}", partnerId, this.authorizationHeader);
            throw new AuthorizationFailedException("Authorization context not valid for operations as '" + partnerId + "'");
        }
    }

}
