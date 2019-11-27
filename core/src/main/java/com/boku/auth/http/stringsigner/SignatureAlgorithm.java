package com.boku.auth.http.stringsigner;

/**
 * Which signature algorithm to use when calling {@link StringSigner}.<br>
 * There's only one right now, more may be added as the need arises (specifically, RSA SHA-256 signatures would come in
 * handy.)
 */
public enum SignatureAlgorithm {

    /**
     * SHA-256 HMAC, encoded as a 64 character lower-case hexadecimal string
     */
    HMAC_SHA256

}
