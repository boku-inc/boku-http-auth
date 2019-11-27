package com.boku.auth.http.server.servletfilter;

import java.security.DigestInputStream;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.util.DigestFactory;
import com.boku.util.HexCodec;

/**
 * Internal util class for functions shared by {@link BokuHttpAuthFilter} related stuff.
 */
class BHAServletUtil {

    private static final String SHA256_EMPTY_DIGEST = HexCodec.encodeString(DigestFactory.getSHA256().digest(new byte[0]));

    /**
     * Extract exactly one parsed {@link AuthorizationHeader} from the given servlet request, throwing if it's invalid.
     */
    static AuthorizationHeader getAuthorizationHeader(HttpServletRequest request) throws InvalidAuthorizationHeaderException {
        Enumeration<String> authHeaders = request.getHeaders(AuthorizationHeader.REQUEST_HEADER);
        if (authHeaders == null) {
            throw new IllegalStateException("Servlet implementation did not supply headers");
        }
        if (!authHeaders.hasMoreElements()) {
            throw new InvalidAuthorizationHeaderException("No " + AuthorizationHeader.REQUEST_HEADER + " header provided");
        }
        String authHeaderValue = authHeaders.nextElement();
        if (authHeaders.hasMoreElements()) {
            throw new InvalidAuthorizationHeaderException("Multiple " + AuthorizationHeader.REQUEST_HEADER + " headers provided");
        }
        try {
            return AuthorizationHeader.parse(authHeaderValue);
        } catch (IllegalArgumentException ex) {
            throw new InvalidAuthorizationHeaderException("Invalid " + AuthorizationHeader.REQUEST_HEADER + " header: " + ex.getMessage());
        }
    }

    /**
     * Return the digest from the given {@link DigestInputStream}, or null if zero bytes have been read through the stream.
     */
    static String getEntityDigest(DigestInputStream dis) {
        String digest = HexCodec.encodeString(dis.getMessageDigest().digest());
        if (SHA256_EMPTY_DIGEST.equals(digest)) {
            return null;
        }
        return digest;
    }

}
