package com.boku.auth.http.server.servletfilter;

import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.httpmessage.CanonicalHttpHeader;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.server.servletfilter.ThreadLocalServletRequestContextHolder.ServletRequestContext;
import com.boku.auth.http.server.spi.CurrentRequestAuthInfo;
import com.boku.auth.http.server.spi.CurrentRequestAuthInfoFactory;

/**
 * Implements {@link CurrentRequestAuthInfoFactory} by interacting with thread-local data stored by
 * {@link BokuHttpAuthFilter}.
 */
public class BokuHttpAuthFilterCurrentRequestAuthInfoFactory implements CurrentRequestAuthInfoFactory {

    private final ThreadLocalServletRequestContextHolder threadLocalRequestContextHolder;

    public BokuHttpAuthFilterCurrentRequestAuthInfoFactory(ThreadLocalServletRequestContextHolder threadLocalServletRequestContextHolder) {
        this.threadLocalRequestContextHolder = threadLocalServletRequestContextHolder;
    }

    @Override
    public CurrentRequestAuthInfo getCurrentRequestInfo() throws InvalidAuthorizationHeaderException {
        ServletRequestContext reqCtx = this.threadLocalRequestContextHolder.get();
        if (reqCtx == null) {
            throw new IllegalStateException("No request context set up by filter. Please install "
                    + BokuHttpAuthFilter.class.getCanonicalName() + " or equivalent.");
        }

        AuthorizationHeader authHeader = BHAServletUtil.getAuthorizationHeader(reqCtx.httpRequest);

        // This surfaced only in some testing with faulty ServletRequest mocks. Might as well have a nice message though.
        if (reqCtx.requestEntityDigestInputStream == null) {
            throw new IllegalStateException("No requestEntityDigestInputStream set on ServletRequestContext. "
                    + "This should never happen, because the only time it's null is when the above Authorization "
                    + "header check would fail.");
        }

        if (reqCtx.cachedEntityDigest == null) {
            // cache the entityDigest of reqCtx.requestEntityDigestInputStream
            reqCtx.cachedEntityDigest = BHAServletUtil.getEntityDigest(reqCtx.requestEntityDigestInputStream);
        }

        String entityDigest = reqCtx.cachedEntityDigest;

        CanonicalHttpRequest canonicalRequest = createCanonicalHttpRequest(reqCtx.httpRequest, authHeader.getSignedHeaders(), entityDigest);

        return new CurrentRequestAuthInfo(authHeader, canonicalRequest);
    }

    private static CanonicalHttpRequest createCanonicalHttpRequest(HttpServletRequest servletRequest, List<String> signedHeaders, String entityDigest) throws InvalidAuthorizationHeaderException {
        CanonicalHttpRequest canonicalRequest = new CanonicalHttpRequest();

        canonicalRequest.setMethod(servletRequest.getMethod());
        canonicalRequest.setPath(servletRequest.getRequestURI());
        canonicalRequest.setQueryString(servletRequest.getQueryString());

        List<CanonicalHttpHeader> canonicalHeaders = canonicalRequest.getHeaders();
        for (String signedHeaderName : signedHeaders) {
            Enumeration<String> signedHeaderValues = servletRequest.getHeaders(signedHeaderName);
            if (signedHeaderValues == null || !signedHeaderValues.hasMoreElements()) {
                throw new InvalidAuthorizationHeaderException("signed-headers specified " + signedHeaderName + ", but was not found");
            }
            while (signedHeaderValues.hasMoreElements()) {
                String headerValue = signedHeaderValues.nextElement();
                canonicalHeaders.add(new CanonicalHttpHeader(signedHeaderName, headerValue.trim()));
            }
        }

        canonicalRequest.setEntityDigest(entityDigest);

        return canonicalRequest;
    }
}
