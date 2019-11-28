package com.boku.auth.http.server.servletfilter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.server.AuthorizationContextProvider;
import com.boku.auth.http.exception.InvalidApplicationSuppliedAuthorizationHeaderException;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.server.factory.ServerAuthorizationComponentsFactory;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.util.DigestFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stores information about the request so that it may be accessed by the application using
 * {@link AuthorizationContextProvider}.<br>
 * <br>
 * WARNING: This filter DOES NOT reject requests based on auth information by itself.
 */
public class BokuHttpAuthFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(BokuHttpAuthFilter.class);

    private final List<String> signedResponseHeaders = new ArrayList<>(Collections.singletonList("Content-Type"));

    private final boolean staticInit;
    private ThreadLocalServletRequestContextHolder threadLocalRequestContext;
    private BokuHttpAuthFilterResponseSigner responseSigner;

    private boolean tomcatWarningChecked = false;

    /**
     * Constructor for users supporting dependency injection.<br>
     * (Either via manual filter registration, or using a shim such as org.springframework.web.filter.DelegatingFilterProxy)
     */
    public BokuHttpAuthFilter(ThreadLocalServletRequestContextHolder threadLocalRequestContextHolder,
                              HttpMessageSigner httpMessageSigner) {
        this.staticInit = false;
        this.threadLocalRequestContext = threadLocalRequestContextHolder;
        this.responseSigner = new BokuHttpAuthFilterResponseSigner(httpMessageSigner);
    }

    /**
     * Servlet-style constructor, uses whatever {@link ServerAuthorizationComponentsFactory#getInstance()} returns.<br>
     * See {@link #init} for details on configuration params.
     *
     * @see #init(FilterConfig)
     */
    public BokuHttpAuthFilter() {
        this.staticInit = true;
    }

    /**
     * Servlet init method.<br>
     * <br>
     * Per-instance params:<ul>
     *     <li><i>com.boku.auth.http.server.response.signed-headers</i>: comma-separated list of headers to sign if they
     *     are present in the response. Defaults to just 'Content-Type'.</li>
     * </ul>
     * Global params:<ul>
     *     <li><i>com.boku.auth.keyprovider.type</i>: how to get a {@link com.boku.auth.http.keyprovider.KeyProvider KeyProvider}. One of 'PKCS12' (default, get keys from a PKCS12 key store) or 'custom' (get any kind of KeyProvider instance from a static factory method).</li>
     *     <li><i>com.boku.auth.keyprovider.pkcs12.file</i>: path to a PKCS12 file. Defaults to 'boku-auth-keys.p12' in the current directory. See documentation on {@link com.boku.auth.http.keyprovider.KeystoreKeyProvider} for how to populate this file.</li>
     *     <li><i>com.boku.auth.keyprovider.pkcs12.password</i>: the password for the PKCS12 file referenced by com.boku.auth.keyprovider.pkcs12.file</li>
     *     <li><i>com.boku.auth.keyprovider.custom.factory-method</i>: name of a public static method, taking no arguments, that will return a KeyProvider instance of some kind. E.g. com.example.SuperSecureKeyProviderFactory.getInstance</li>
     * </ul>
     *
     * @param filterConfig The FilterConfig containing init params
     */
    @Override
    public void init(FilterConfig filterConfig) {
        LinkedHashMap<String, String> initParams = new LinkedHashMap<>();
        Enumeration<String> paramNames = filterConfig.getInitParameterNames();
        while (paramNames.hasMoreElements()) {
            String name = paramNames.nextElement();
            initParams.put(name, filterConfig.getInitParameter(name));
        }

        String signedHeaders = initParams.get("com.boku.auth.http.server.response.signed-headers");
        if (signedHeaders != null) {
            this.signedResponseHeaders.clear();
            for (String part : signedHeaders.split(",")) {
                String headerName = part.trim();
                if (headerName.length() > 0) {
                    this.signedResponseHeaders.add(headerName);
                }
            }
        }

        if (this.staticInit) {
            ServerAuthorizationComponentsFactory.init(initParams);

            ServerAuthorizationComponentsFactory factory = ServerAuthorizationComponentsFactory.getInstance();
            this.threadLocalRequestContext = factory.getThreadLocalServletRequestContextHolder();
            this.responseSigner = new BokuHttpAuthFilterResponseSigner(factory.getHttpMessageSigner());
        }
    }

    private MessageDigest getEntityDigester() {
        // This will depend on Authorization header in future
        return DigestFactory.getSHA256();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        HttpServletResponse httpResponse = (HttpServletResponse)response;

        // First check if auth processing is even necessary.
        //
        // If the client did not supply an Authorization header, still store the request info in the thread-local so
        // that the error can be surfaced at the application's discretion, but don't waste CPU and memory digesting and
        // buffering the entities because we're never going to use that information.

        if (httpRequest.getHeader(AuthorizationHeader.REQUEST_HEADER) == null) {
            logger.debug("Not doing auth processing for {} {}, because no Authorization header supplied",
                    httpRequest.getMethod(), httpRequest.getRequestURI());
            this.threadLocalRequestContext.open(httpRequest, null);
            try {
                chain.doFilter(httpRequest, httpResponse);
            } finally {
                this.threadLocalRequestContext.close();
            }
            return;
        }

        if (!this.tomcatWarningChecked) {
            checkTomcat(response);
            this.tomcatWarningChecked = true;
        }

        // Listen in on the request InputStream and make a digest of everything that goes through
        final DigestInputStream digestInputStream = new DigestInputStream(
                request.getInputStream(),
                this.getEntityDigester()
        );

        // Also buffer the OutputStream, so we can sign the response when done.
        final ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();

        // Set up the thread-local, so while the child filters are running they have access to the context
        this.threadLocalRequestContext.open(httpRequest, digestInputStream);
        int requestContextAccessCount;
        try {
            logger.debug("Invoking filter chain for {} {}...", httpRequest.getMethod(), httpRequest.getRequestURI());

            // Invoke the chain with our spies in place.
            chain.doFilter(
                    new HttpServletRequestWrapper(httpRequest) {

                        @Override
                        public ServletInputStream getInputStream() {
                            return new InputStreamAsServletInputStream(digestInputStream);
                        }
                    },
                    new HttpServletResponseWrapper(httpResponse) {
                        @Override
                        public ServletOutputStream getOutputStream() {
                            return new ServletOutputStream() {
                                @Override
                                public void write(int b) {
                                    outputBuffer.write(b);
                                }
                                @Override
                                public boolean isReady() {
                                    return true;
                                }
                                @Override
                                public void setWriteListener(WriteListener writeListener) {
                                    throw new UnsupportedOperationException();
                                }
                            };
                        }
                    }
            );

            requestContextAccessCount = this.threadLocalRequestContext.getAccessCount();

        } finally {
            this.threadLocalRequestContext.close();
        }

        if (requestContextAccessCount == 0) {
            logger.warn("Request information was not accessed for request to {} {}, i.e. auth info was not checked!",
                    httpRequest.getMethod(), httpRequest.getRequestURI());
        } else {
            logger.debug("Done invoking filter chain for {} {}, request auth info accessed {} times",
                    httpRequest.getMethod(), httpRequest.getRequestURI(), requestContextAccessCount);
        }

        // We're done running the request, time to sign the response
        byte[] respData = outputBuffer.toByteArray();

        // Try and get the auth header so we can use the referenced key, otherwise don't sign the response
        AuthorizationHeader requestAuthHeader;
        try {
            requestAuthHeader = BHAServletUtil.getAuthorizationHeader(httpRequest);
        } catch (InvalidAuthorizationHeaderException ex) {
            logger.debug("Not signing response to {} {}, because request had invalid Authorization header: {}",
                    httpRequest.getMethod(), httpRequest.getRequestURI(), ex.getMessage());
            response.getOutputStream().write(respData);
            return;
        }

        logger.debug("Signing response to {} {} based on info in request auth header: {}",
                httpRequest.getMethod(), httpRequest.getRequestURI(), requestAuthHeader);

        try {
            AuthorizationHeader respAuthHeader = this.responseSigner.signResponse(
                    requestAuthHeader, this.signedResponseHeaders,
                    httpResponse, respData
            );
            logger.debug("Sending response Authorization header: {}", respAuthHeader);
            httpResponse.setHeader(AuthorizationHeader.RESPONSE_HEADER, respAuthHeader.toString());
        } catch (InvalidApplicationSuppliedAuthorizationHeaderException ex) {
            // This is expected when the inbound Authorization header referred to an invalid partner or key ID
            logger.error("Failed to sign response to {} {}: {} (inbound request Authorization header: {})",
                    httpRequest.getMethod(), httpRequest.getRequestURI(), ex.toString(), requestAuthHeader
            );
        }

        response.getOutputStream().write(respData);
    }

    /**
     * Check if we're running under Tomcat and warn appropriately.<br>
     * <br>
     * Tomcat's Response class has a non-functional {@link HttpServletResponse#getHeaders(String) getHeaders} method,
     * so the values need be be captured in a response wrapper. It also mangles the value of the Content-Type header
     * before sending it, which means the captured value cannot be signed - instead we need to reproduce the Tomcat
     * mangling behavior before capturing.<br>
     * This <i>can</i> all be worked around, but the code to do so has been removed to reduce unnecessary complexity
     * after Tomcat was purged from the Boku platform. If you need Tomcat signed headers support to be re-introduced,
     * please contact support to request as such.
     */
    private void checkTomcat(ServletResponse response) {
        if (response.getClass().getCanonicalName().startsWith("org.apache.catalina")) {
            logger.warn("Running under Tomcat with broken HttpServletResponse.setHeader/getHeaders support! " +
                "Response headers will not be signed: {}. Please see comment on {}.checkTomcat() method for more info.",
                this.signedResponseHeaders, this.getClass().getSimpleName()
            );
        }
    }

    @Override
    public void destroy() {
    }

}
