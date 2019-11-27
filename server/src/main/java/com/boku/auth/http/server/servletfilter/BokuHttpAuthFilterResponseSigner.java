package com.boku.auth.http.server.servletfilter;

import java.util.Collection;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.httpmessage.CanonicalHttpHeader;
import com.boku.auth.http.httpmessage.CanonicalHttpResponse;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.util.DigestFactory;
import com.boku.util.HexCodec;

/**
 * Does the work of signing {@link HttpServletResponse}s from {@link BokuHttpAuthFilter}
 */
class BokuHttpAuthFilterResponseSigner {

    private final HttpMessageSigner httpMessageSigner;

    BokuHttpAuthFilterResponseSigner(HttpMessageSigner httpMessageSigner) {
        this.httpMessageSigner = httpMessageSigner;
    }

    AuthorizationHeader signResponse(AuthorizationHeader requestAuthHeader, List<String> headersToSign, HttpServletResponse httpResponse, byte[] respData) {

        // This is the header we're going to output.
        // We take partner ID and key ID from the request header, i.e. this is symmetric. In future we may want to
        // allow the key provider to pick the key for signing messages to allow for asymmetric signatures.
        AuthorizationHeader respAuthHeader = new AuthorizationHeader();
        respAuthHeader.setPartnerId(requestAuthHeader.getPartnerId());
        respAuthHeader.setKeyId(requestAuthHeader.getKeyId());

        // Create canonical response object, while setting the correct list of signed-headers
        CanonicalHttpResponse canonicalResponse = new CanonicalHttpResponse();
        for (String hdr : headersToSign) {
            Collection<String> values = httpResponse.getHeaders(hdr);
            if (values == null || values.isEmpty()) {
                continue;
            }
            respAuthHeader.getSignedHeaders().add(hdr);
            for (String value : values) {
                canonicalResponse.getHeaders().add(new CanonicalHttpHeader(hdr, value.trim()));
            }
        }
        if (respData.length > 0) {
            byte[] digest = DigestFactory.getSHA256().digest(respData);
            canonicalResponse.setEntityDigest(HexCodec.encodeString(digest));
        }

        // Fill in missing values and sign
        this.httpMessageSigner.sign(respAuthHeader, canonicalResponse);

        return respAuthHeader;
    }

}
