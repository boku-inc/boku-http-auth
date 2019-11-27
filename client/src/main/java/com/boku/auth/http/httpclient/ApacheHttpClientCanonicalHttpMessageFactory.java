package com.boku.auth.http.httpclient;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Iterator;
import java.util.List;

import com.boku.auth.http.httpmessage.CanonicalHttpMessage;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.util.DigestFactory;
import com.boku.util.HexCodec;
import com.boku.auth.http.httpmessage.CanonicalHttpHeader;
import com.boku.util.IO;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;

import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.httpmessage.CanonicalHttpResponse;

/**
 * Utility encapsulating most of the business of converting Apache {@link HttpClient} requests and responses to the
 * {@link CanonicalHttpMessage} format used by the {@link HttpMessageSigner}
 */
public class ApacheHttpClientCanonicalHttpMessageFactory {

    /**
     * Given a HttpClient request and a list of headers to sign, translate into a {@link CanonicalHttpRequest}, reading
     * the contents of the request entity if present and repeatable.
     *
     * @param signedHeaders A list of headers to sign, as will appear in the Authorization header. This list will be
     *                      modified in-place to remove any headers that do not appear in the actual request.
     * @param request The HttpClient request
     * @return A {@link CanonicalHttpRequest} instance.
     */
    public CanonicalHttpRequest createRequest(List<String> signedHeaders, HttpUriRequest request) {
        HttpEntity httpEntity = null;
        if (request instanceof HttpEntityEnclosingRequest) {
            httpEntity = ((HttpEntityEnclosingRequest)request).getEntity();
        }
        if (httpEntity == null) {
            return createRequest(signedHeaders, request, null);
        }

        if (!httpEntity.isRepeatable()) {
            throw new IllegalStateException("Cannot read entity data from " + request + " because the entity is not " +
                "repeatable! Either use a repeatable entity, or use the 3-argument form of createRequest"
            );
        }

        byte[] entityData;
        try (InputStream is = httpEntity.getContent()) {
            entityData = IO.toByteArray(is);
        } catch (IOException ex) {
            throw new IllegalStateException("IO error reading repeatable entity on " + request + ". I'm not sure why " +
                "this would happen, but maybe your problem can be fixed by using the 3-argument form of createRequest",
                ex
            );
        }

        return createRequest(signedHeaders, request, entityData);
    }

    /**
     * Same as {@link #createRequest(List, HttpUriRequest)}, but takes explicit entity data instead.<br>
     * There shouldn't really be any reason to use this method - if you have all the entity contents in memory anyway,
     * just use a ByteArrayEntity or StringEntity when you create your HttpRequest.
     *
     * @param signedHeaders A list of headers to sign, as will appear in the Authorization header. This list will be
     *                      modified in-place to remove any headers that do not appear in the actual request.
     * @param request The HttpClient request
     * @param entity Request entity, if present, null otherwise.
     * @return A {@link CanonicalHttpRequest} instance.
     */
    public CanonicalHttpRequest createRequest(List<String> signedHeaders, HttpUriRequest request, byte[] entity) {
        CanonicalHttpRequest canonicalRequest = new CanonicalHttpRequest();

        // Request line
        canonicalRequest.setMethod(request.getMethod());
        URI uri = request.getURI();
        canonicalRequest.setPath(uri.getRawPath());
        canonicalRequest.setQueryString(uri.getRawQuery());

        // Include all headers referenced by the AuthorizationHeader, and remove any from the signed-headers list
        // that are not present.
        Iterator<String> itr = signedHeaders.iterator();
        while (itr.hasNext()) {
            String headerName = itr.next();
            Header[] headers = request.getHeaders(headerName);
            int headerCount = 0;
            for (Header header : headers) {
                String headerValue = header.getValue();
                if (headerValue != null) {
                    canonicalRequest.getHeaders().add(new CanonicalHttpHeader(headerName, headerValue.trim()));
                    headerCount++;
                }
            }
            if (headerCount == 0) {
                itr.remove();
            }
        }

        // Entity
        if (entity != null && entity.length > 0) {
            String entityDigest = HexCodec.encodeString(DigestFactory.getSHA256().digest(entity));
            canonicalRequest.setEntityDigest(entityDigest);
        }

        return canonicalRequest;
    }

    /**
     * @param signedHeaders The list of signed-headers as returned in the response X-SignedResponse header
     * @param response HttpClient response object
     * @param entityData Returned raw response entity data
     * @return A {@link CanonicalHttpResponse}
     */
    public CanonicalHttpResponse createResponse(List<String> signedHeaders, HttpResponse response, byte[] entityData) {
        CanonicalHttpResponse canonicalResponse = new CanonicalHttpResponse();

        // Headers
        for (String headerName : signedHeaders) {
            for (Header header : response.getHeaders(headerName)) {
                canonicalResponse.getHeaders().add(new CanonicalHttpHeader(headerName, header.getValue()));
            }
        }

        // Entity
        if (entityData != null && entityData.length > 0) {
            canonicalResponse.setEntityDigest(HexCodec.encodeString(DigestFactory.getSHA256().digest(entityData)));
        }

        return canonicalResponse;
    }
}
