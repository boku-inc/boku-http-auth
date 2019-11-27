package com.boku.auth.http.server.servletfilter;

import java.security.DigestInputStream;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Internal implementation class.<br>
 * <br>
 * {@link BokuHttpAuthFilter} sticks information about the request it's currently working on here, so that
 * {@link BokuHttpAuthFilterCurrentRequestAuthInfoFactory} can access it.
 */
public class ThreadLocalServletRequestContextHolder {

    private static final Logger logger = LoggerFactory.getLogger(ThreadLocalServletRequestContextHolder.class);

    private final ThreadLocal<ServletRequestContext> threadLocalRequestContext = new ThreadLocal<>();

    void open(HttpServletRequest httpRequest, DigestInputStream digestInputStream) {
        if (this.threadLocalRequestContext.get() != null) {
            logger.warn("ThreadLocal ServletRequestContext was not closed out properly! Overwriting existing value...");
        }
        this.threadLocalRequestContext.set(new ServletRequestContext(httpRequest, digestInputStream));
    }

    ServletRequestContext get() {
        ServletRequestContext ret = this.threadLocalRequestContext.get();
        if (ret != null) {
            ret.accessCount++;
        }
        return ret;
    }

    int getAccessCount() {
        return this.threadLocalRequestContext.get().accessCount;
    }

    void close() {
        if (this.threadLocalRequestContext.get() == null) {
            logger.warn("ThreadLocal ServletRequestContext already closed!");
        }
        this.threadLocalRequestContext.set(null);
    }


    static class ServletRequestContext {

        /**
         * Current {@link HttpServletRequest}.
         */
        final HttpServletRequest httpRequest;

        /**
         * {@link DigestInputStream} wrapping the servlet InputStream for the request.
         * This may be null if there was no auth info supplied in the request above.
         */
        final DigestInputStream requestEntityDigestInputStream;

        /**
         * {@link DigestInputStream} can only get digested once.
         * Cache the entityDigest from requestEntityDigestInputStream.
         */
        String cachedEntityDigest;

        int accessCount = 0;

        ServletRequestContext(HttpServletRequest httpRequest, DigestInputStream dis) {
            this.httpRequest = httpRequest;
            this.requestEntityDigestInputStream = dis;
        }
    }

}
