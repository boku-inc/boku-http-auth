package com.boku.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Util for getting {@link MessageDigest}s.
 *
 * Note if we need to support other types of entity digest, we will need to plug in support for getting a digest based
 * on the scheme referenced in the Authorization header.
 */
public class DigestFactory {

    public static MessageDigest getSHA256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 not available?", ex);
        }
    }
}
