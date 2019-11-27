package com.boku.auth.http.keyprovider;

import com.boku.auth.http.AuthorizationHeader;

/**
 * Retrieve an API key by {@link AuthorizationHeader#getPartnerId() partner ID} and
 * {@link AuthorizationHeader#getKeyId() key ID}.
 */
public interface KeyProvider {

    /**
     * Retrieve a key by the given partner ID and key ID.
     *
     * @param partnerId Partner ID, e.g. "my-merchant"
     * @param keyId Key ID to sign with, e.g. "1"
     * @return The key in string format if found, null otherwise
     */
    String get(String partnerId, String keyId);
}
