package com.boku.auth.http.server.spi;

import com.boku.auth.http.server.AuthorizationContextProvider;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.server.servletfilter.BokuHttpAuthFilterCurrentRequestAuthInfoFactory;

/**
 * Implemented in the context of a specific HTTP framework (such as Servlet) to return auth info in a common form so
 * that it can be verified by the core authentication code.<br>
 * <br>
 * This interface exists mainly just-in-case - practically this should almost always be accomplished via the
 * {@link BokuHttpAuthFilterCurrentRequestAuthInfoFactory servlet implementation},
 * and any higher level framework integration (such as Jersey or SpringMVC) can be responsible for simply calling
 * {@link AuthorizationContextProvider}.
 */
public interface CurrentRequestAuthInfoFactory {

    /**
     * @return Get the {@link CurrentRequestAuthInfo} for the currently executing request. Does not return null.
     * @throws InvalidAuthorizationHeaderException If an Authorization header was not presented with the request
     *         (i.e. it cannot be authenticated), or there was some basic formatting problem with said header.
     * @throws IllegalStateException If called outside the scope of a request.
     */
    CurrentRequestAuthInfo getCurrentRequestInfo() throws InvalidAuthorizationHeaderException;

}
