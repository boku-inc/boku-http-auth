package com.boku.auth.http.client;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Set;

import com.boku.auth.http.client.exception.BokuAPIClientException;
import com.boku.auth.http.httpclient.ApacheHttpClientCanonicalHttpMessageFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.AuthorizationException;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.httpmessage.CanonicalHttpResponse;
import com.boku.auth.http.httpsigner.HttpMessageSigner;

/**
 * Wrapper around Apache {@link HttpClient} and the Boku authentication {@link HttpMessageSigner}, allowing you to
 * easily make authenticated API calls.<br>
 * <br>
 * Focus is on typical API calls only - entire requests and responses are buffered in memory so not a general HTTP
 * client.
 */
public class BokuAPIClient {

    private static final Logger logger = LoggerFactory.getLogger(BokuAPIClient.class);

    private static final Set<Integer> NO_ENTITY_STATUS_CODES = Collections.singleton(
        HttpStatus.SC_NO_CONTENT
    );

    private final ApacheHttpClientCanonicalHttpMessageFactory canonicalHttpMessageFactory = new ApacheHttpClientCanonicalHttpMessageFactory();

    private final HttpClient httpClient;
    private final HttpMessageSigner httpSigner;
    private final Charset requestCharset;
    private final EntityMarshaller entityMarshaller;
    private final String entityMarshallerContentType;

    /**
     * Create a client instance configured with the given entity marshaller and request charset.
     *
     * @param httpClient An instance of {@link HttpClient} configured however preferred.
     *                   <b>NOTE:</b> it is strongly recommended the HttpClient is configured with automatic redirect
     *                   support disabled for security purposes - the signature of an automatically handled redirect
     *                   will not be checked by this client.
     * @param httpSigner An instance of {@link HttpMessageSigner}, used to sign outgoing requests, and verify
     *                   signatures on responses.
     * @param entityMarshaller An {@link EntityMarshaller} instance, if desired, null otherwise.
     * @param requestCharset Charset to use when encoding text to send in the request body. If null, defaults to UTF-8.
     */
    public BokuAPIClient(HttpClient httpClient, HttpMessageSigner httpSigner, EntityMarshaller entityMarshaller, Charset requestCharset) {
        this.httpClient = httpClient;
        this.httpSigner = httpSigner;
        this.requestCharset = requestCharset != null ? requestCharset : StandardCharsets.UTF_8;
        this.entityMarshaller = entityMarshaller;
        if (entityMarshaller == null) {
            this.entityMarshallerContentType = null;
        } else if (entityMarshaller.getContentType().contains(";")) {
            logger.warn("Entity marshaller {} has Content-Type '{}' which already contains parameters. " +
                "Will use as-is instead of appending charset {}",
                entityMarshaller, entityMarshaller.getContentType(), this.requestCharset
            );
            this.entityMarshallerContentType = entityMarshaller.getContentType();
        } else {
            this.entityMarshallerContentType = entityMarshaller.getContentType() + "; charset=\"" + this.requestCharset + '"';
        }
    }

    /**
     * Create a client instance configured with no entity marshaller and the given request charset.
     *
     * @see #BokuAPIClient(HttpClient, HttpMessageSigner, EntityMarshaller, Charset)
     */
    public BokuAPIClient(HttpClient httpClient, HttpMessageSigner httpSigner, Charset requestCharset) {
        this(httpClient, httpSigner, null, requestCharset);
    }

    /**
     * Create a client instance configured with the given entity marshaller and the default request charset of UTF-8.
     *
     * @see #BokuAPIClient(HttpClient, HttpMessageSigner, EntityMarshaller, Charset)
     */
    public BokuAPIClient(HttpClient httpClient, HttpMessageSigner httpSigner, EntityMarshaller entityMarshaller) {
        this(httpClient, httpSigner, entityMarshaller, null);
    }

    /**
     * Create a client instance configured with no entity marshaller and the default request charset of UTF-8.
     *
     * @see #BokuAPIClient(HttpClient, HttpMessageSigner, EntityMarshaller, Charset)
     */
    public BokuAPIClient(HttpClient httpClient, HttpMessageSigner httpSigner) {
        this(httpClient, httpSigner, null, null);
    }

    /**
     * Obtain a POST {@link RequestBuilder} for the given URL
     *
     * @param url A fully qualified API URL, e.g. "https://us-api4.boku.com/optin/3.0/optin"
     * @return A {@link RequestBuilder}
     */
    public RequestBuilder post(String url) {
        return new RequestBuilder(new HttpPost(url));
    }

    /**
     * Obtain a PUT {@link RequestBuilder} for the given URL
     *
     * @param url A fully qualified API URL, e.g. "https://us-api4.boku.com/optin/3.0/optin"
     * @return A {@link RequestBuilder}
     */
    public RequestBuilder put(String url) {
        return new RequestBuilder(new HttpPut(url));
    }

    /**
     * Obtain a GET {@link RequestBuilder} for the given URL
     *
     * @param url A fully qualified API URL, e.g. "https://us-api4.boku.com/optin/3.0/optin"
     * @return A {@link RequestBuilder}
     */
    public RequestBuilder get(String url) {
        return new RequestBuilder(new HttpGet(url));
    }

    /**
     * Obtain a DELETE {@link RequestBuilder} for the given URL
     *
     * @param url A fully qualified API URL, e.g. "https://us-api4.boku.com/optin/3.0/optin"
     * @return A {@link RequestBuilder}
     */
    public RequestBuilder delete(String url) {
        return new RequestBuilder(new HttpDelete(url));
    }

    /**
     * High level interface to build up a request
     */
    public class RequestBuilder {

        private final HttpUriRequest request;
        private AuthorizationHeader authHeader;
        private String entityString;
        private boolean verifyResponseSignature = true;

        private RequestBuilder(HttpUriRequest request) {
            this.request = request;
        }

        /**
         * Use the given {@link AuthorizationHeader} as the basis for signing the request.<br>
         * Only partnerId and keyId are required to be specified, the rest will be filled out automatically based on
         * the request itself.<br>
         * If you wish to fully specify the contents of the Authorization header, use {@link #withHeader} instead.
         */
        public RequestBuilder withAuthorization(AuthorizationHeader authHeader) {
            this.authHeader = authHeader;
            return this;
        }

        /**
         * Send the given header value with the request.<br>
         * Each header added via this method will also be included in the signature of the request.
         *
         * @param name The HTTP header name as it will appear in the request.
         * @param value Header value
         */
        public RequestBuilder withHeader(String name, String value) {
            this.request.addHeader(name, value);
            if (this.authHeader != null) {
                for (String signedHeaderName : this.authHeader.getSignedHeaders()) {
                    if (signedHeaderName.equalsIgnoreCase(name)) {
                        return this;
                    }
                }
                this.authHeader.getSignedHeaders().add(name);
            }
            return this;
        }

        /**
         * Use the given string as the entity text directly.
         */
        public RequestBuilder withEntityString(String entity) {
            this.entityString = entity;
            if (entity == null) {
                return this;
            }

            if (!(this.request instanceof HttpEntityEnclosingRequest)) {
                throw new IllegalStateException(this.request.getMethod() + " requests cannot accept an entity ("
                                                + this.request.getURI() + ")");
            }

            HttpEntity requestEntity = new StringEntity(entity, requestCharset);
            ((HttpEntityEnclosingRequest)this.request).setEntity(requestEntity);

            return this;
        }

        /**
         * Given an object marshallable via the configured {@link EntityMarshaller}, marshal it to text and use the
         * result as the request entity.<br>
         * The Content-Type header will be set appropriately.
         */
        public RequestBuilder withEntity(Object entity) {
            if (entityMarshaller == null) {
                throw new IllegalStateException("Cannot marshal request entity, no EntityMarshaller supplied");
            }
            return this
                .withHeader("Content-Type", entityMarshallerContentType)
                .withEntityString(entityMarshaller.marshal(entity));
        }

        /**
         * Option to set whether the response signature should be verified.
         * Defaults to true if not set.
         */
        public RequestBuilder withVerifyResponseSignature(boolean verifyResponseSignature) {
            this.verifyResponseSignature = verifyResponseSignature;
            return this;
        }

        /**
         * Internal method called by the other variants of {@link #execute}.
         */
        private BokuAPIClientResponse executeAndReturnAPIResponse() throws IOException, BokuAPIClientException {

            // Sign and set Authorization header if requested
            AuthorizationHeader authHeader = this.getSignedAuthorizationHeader();
            if (authHeader != null) {
                this.request.setHeader(AuthorizationHeader.REQUEST_HEADER, authHeader.toString());
            }

            logRequest(this.request, this.entityString);

            // Execute the request and convert it into API client response, fully reading in any entity data
            HttpResponse httpResponse = httpClient.execute(this.request);
            BokuAPIClientResponse apiClientResponse;
            try {
                apiClientResponse = createBokuAPIClientResponse(httpResponse);
            } catch (IOException ex) {
                throw new IOException("Failed to read from response stream for " + this.request.getURI(), ex);
            }

            logger.debug("Response:\n{}", apiClientResponse);

            // Verify signature on the response
            if (authHeader != null && this.verifyResponseSignature) {
                verifyResponseSignature(httpResponse, apiClientResponse);
            }

            return apiClientResponse;
        }

        /**
         * Execute the request, and return the response as a string. This assumes the server is returning a text
         * content-type.
         *
         * @return The response entity as a string.
         * @throws IOException If thrown by the underlying {@link HttpClient}
         * @throws HttpResponseException If the server returned a non-OK HTTP response
         * @throws BokuAPIClientException If we expected the response to be signed and it did not have a valid
         *                                signature, or if there was any other problem with the response unrelated to
         *                                its HTTP status code.
         */
        public String execute() throws IOException, BokuAPIClientException {
            return this.execute(String.class);
        }

        /**
         * Execute the request, expecting a response that can be unmarshalled to the given responseType.<br>
         * <br>
         * As a special case, passing {@link BokuAPIClientResponse}.class allows access to the raw response data, but
         * <b>note</b> in this case it is up to <i>you</i> to check the HTTP status code using
         * {@link BokuAPIClientResponse#getStatusLine()} - this method will not check for you.
         *
         * @param <T> Response type
         * @param responseType Class of the expected response type
         * @return The entity returned in the response, unmarshalled into an instance of the given responseType.
         * @throws IOException If thrown by the underlying {@link HttpClient}
         * @throws HttpResponseException If the server returned a non-OK HTTP response, <b>unless</b> you requested
         *                               {@link BokuAPIClientResponse} as explained above.
         * @throws BokuAPIClientException If we expected the response to be signed and it did not have a valid
         *                                signature, if the response entity could not be unmarshalled, or if there was
         *                                any other problem with the response unrelated to its HTTP status code.
         */
        public <T> T execute(Class<T> responseType) throws IOException, BokuAPIClientException {
            BokuAPIClientResponse response = this.executeAndReturnAPIResponse();
            if (responseType == BokuAPIClientResponse.class) {
                @SuppressWarnings("unchecked")
                T ret = (T)response;
                return ret;
            }

            StatusLine httpStatus = response.getStatusLine();
            if (httpStatus.getStatusCode() < 200 || httpStatus.getStatusCode() > 299) {
                throw new HttpResponseException(httpStatus.getStatusCode(),
                    httpStatus + ": " + response.getEntity()
                );
            }

            if (response.getEntity() == null) {
                if (NO_ENTITY_STATUS_CODES.contains(httpStatus.getStatusCode())) {
                    return null;
                }
                throw new BokuAPIClientException(
                    "No entity returned in HTTP " + httpStatus.getStatusCode() + " response to " + this.request.getURI(),
                    response
                );
            }

            return response.getEntity().getDataAs(responseType);
        }



        private AuthorizationHeader getSignedAuthorizationHeader() {
            if (this.authHeader == null) {
                return null;
            }

            CanonicalHttpRequest canonicalRequest = canonicalHttpMessageFactory.createRequest(
                this.authHeader.getSignedHeaders(),
                this.request
            );

            httpSigner.sign(this.authHeader, canonicalRequest);

            return this.authHeader;
        }

    }

    private void verifyResponseSignature(HttpResponse httpResponse, BokuAPIClientResponse apiClientResponse) throws BokuAPIClientException {
        Header[] respAuthHeaders = httpResponse.getHeaders(AuthorizationHeader.RESPONSE_HEADER);
        if (respAuthHeaders.length != 1) {
            throw new BokuAPIClientException(
                "Got " + httpResponse.getStatusLine() + " with " + respAuthHeaders.length + " " + AuthorizationHeader.RESPONSE_HEADER + " headers, expected 1!",
                apiClientResponse
            );
        }
        String respAuthHeaderValue = respAuthHeaders[0].getValue();

        AuthorizationHeader respAuthHeader;
        try {
            respAuthHeader = AuthorizationHeader.parse(respAuthHeaderValue);
        } catch (IllegalArgumentException ex) {
            throw new BokuAPIClientException(
                "Invalid " + AuthorizationHeader.RESPONSE_HEADER + " header: " + ex.getMessage()
                + " (header value: " + respAuthHeaderValue + ")",
                apiClientResponse
            );
        }

        CanonicalHttpResponse canonicalResponse = canonicalHttpMessageFactory.createResponse(
            respAuthHeader.getSignedHeaders(),
            httpResponse,
            apiClientResponse.getEntity() == null ? null : apiClientResponse.getEntity().getData()
        );

        try {
            httpSigner.verifySignature(respAuthHeader, canonicalResponse);
        } catch (AuthorizationException ex) {
            throw new BokuAPIClientException("Failed to verify signature of " + httpResponse.getStatusLine() + " response", apiClientResponse, ex);
        }
    }

    private BokuAPIClientResponse createBokuAPIClientResponse(HttpResponse httpResponse) throws IOException {
        ContentType entityContentType = null;
        byte[] entityData = null;
        try {
            HttpEntity httpEntity = httpResponse.getEntity();
            if (httpEntity != null) {
                entityContentType = ContentType.get(httpEntity);
                if (entityContentType == null) {
                    entityContentType = ContentType.APPLICATION_OCTET_STREAM;
                }
                entityData = EntityUtils.toByteArray(httpEntity);
            }
        } finally {
            EntityUtils.consumeQuietly(httpResponse.getEntity());
        }

        return new BokuAPIClientResponse(this.entityMarshaller, httpResponse, entityContentType, entityData);
    }

    private static void logRequest(HttpUriRequest request, String entityString) {
        if (!logger.isDebugEnabled()) {
            return;
        }
        StringBuilder sb = new StringBuilder(request.getMethod()).append(' ').append(request.getURI());
        for (Header header : request.getAllHeaders()) {
            sb.append('\n').append(header.getName()).append(": ").append(header.getValue());
        }
        if (entityString != null) {
            sb.append("\n\n").append(entityString);
        }
        logger.debug("Request:\n{}", sb);
    }
}
