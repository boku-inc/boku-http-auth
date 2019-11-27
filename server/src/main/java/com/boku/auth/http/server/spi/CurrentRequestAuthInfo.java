package com.boku.auth.http.server.spi;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;

/**
 * Represents as-yet <b>UNAUTHENTICATED</b> auth info supplied with a request.<br>
 * <br>
 * This information is to be provided by a specific HTTP framework implementation such as Servlet, Jersey, etc, by
 * means of implementing the {@link CurrentRequestAuthInfoFactory} interface.
 */
public class CurrentRequestAuthInfo {

    private final AuthorizationHeader authorizationHeader;
    private final CanonicalHttpRequest canonicalRequest;

    public CurrentRequestAuthInfo(AuthorizationHeader authorizationHeader, CanonicalHttpRequest canonicalRequest) {
        this.authorizationHeader = authorizationHeader;
        this.canonicalRequest = canonicalRequest;
    }

    /**
     * The parsed Authorization header received with the request. Not be null.
     */
    public AuthorizationHeader getAuthorizationHeader() {
        return this.authorizationHeader;
    }

    /**
     * The canonicalized request. Not null.
     */
    public CanonicalHttpRequest getCanonicalRequest() {
        return this.canonicalRequest;
    }

}
