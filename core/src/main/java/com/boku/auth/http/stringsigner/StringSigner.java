package com.boku.auth.http.stringsigner;

import java.security.InvalidKeyException;

/**
 * Simple interface for signing text data with a particular key, where the implementation owns the key.
 */
public interface StringSigner {

    /**
     * Generate a signature for the given text data, using the given algorithm and a key that will be retrieved using
     * the given partnerId and keyId.
     *
     * @param algorithm One of {@link SignatureAlgorithm}
     * @param partnerId The partner ID under which the key to be used is stored
     * @param keyId The key ID under which the key to be used is stored
     * @param stringToSign The string to sign
     * @return The signature, which is guaranteed to be printable ASCII but is otherwise of an algorithm-specific format
     * @throws InvalidKeyException If the referenced key was not found, or is invalid
     */
    String generateSignature(SignatureAlgorithm algorithm, String partnerId, String keyId, String stringToSign) throws InvalidKeyException;

}
