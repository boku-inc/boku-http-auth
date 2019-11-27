package com.boku.auth.http.stringsigner;

import com.boku.util.HexCodec;
import com.boku.auth.http.keyprovider.KeyProvider;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A simple implementation of {@link StringSigner} which calculates signatures locally, depending only on a
 * {@link KeyProvider}.
 */
public class BasicStringSignerImpl implements StringSigner {

    private static final String HMAC_SHA256 = "HmacSHA256";

    private final KeyProvider keyProvider;

    public BasicStringSignerImpl(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @Override
    public String generateSignature(SignatureAlgorithm algorithm, String partnerId, String keyId, String stringToSign) throws InvalidKeyException {
        if (algorithm != SignatureAlgorithm.HMAC_SHA256) {
            throw new UnsupportedOperationException("Algorithm " + algorithm + " not supported");
        }

        String key = this.keyProvider.get(partnerId, keyId);
        if (key == null) {
            throw new InvalidKeyException("No key found by partnerId=" + partnerId + " and keyId=" + keyId);
        }

        Mac mac = this.getMac(key);

        byte[] hmac = mac.doFinal(toUTF8(stringToSign));

        return HexCodec.encodeString(hmac);
    }

    private Mac getMac(String key) throws InvalidKeyException {
        SecretKeySpec secretKey = new SecretKeySpec(toUTF8(key), HMAC_SHA256);
        Mac mac;
        try {
            mac = Mac.getInstance(HMAC_SHA256);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(HMAC_SHA256 + " is guaranteed to be present", ex);
        }
        mac.init(secretKey);
        return mac;
    }

    private static byte[] toUTF8(String string) {
        return string.getBytes(StandardCharsets.UTF_8);
    }

}
