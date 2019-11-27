package com.boku.auth.http;

import org.junit.Assert;
import org.junit.Test;

public class AuthorizationHeaderTest {

    @Test
    public void testRoundTrip() {
        String[] headers = {
                "2/HMAC_SHA256(H+SHA256(E)) partner-id=bob, key-id=123, signed-headers=Content-Type;X-Forwarded-For, timestamp=140972658382, signature=af5938faf97a7f7a7f778af, requires-canonicalize=true",
                "2/HMAC_SHA256(H+SHA256(E)) partner-id=bob, key-id=123, signed-headers=Content-Type;X-Forwarded-For, timestamp=140972658382, signature=af5938faf97a7f7a7f778af",
                "2/HMAC_SHA256(H+SHA256(E)) partner-id=bob, key-id=123, timestamp=140972658382, signature=af5938faf97a7f7a7f778af"
        };
        for (String headerValue : headers) {
            AuthorizationHeader ah = AuthorizationHeader.parse(headerValue);
            Assert.assertNotNull(ah);
            System.out.println(ah);
            Assert.assertEquals(headerValue, ah.toString());
        }
    }

    /**
     * As an FYI, this is what it does when required fields are null. Should never happen.
     */
    @Test
    public void testNonNullableNullFieldSerialization() {
        AuthorizationHeader ah = AuthorizationHeader.parse("2/HMAC_SHA256(H+SHA256(E)) x=y");
        Assert.assertNotNull(ah);
        Assert.assertEquals("2/HMAC_SHA256(H+SHA256(E)) partner-id=null, key-id=null, timestamp=null, signature=null", ah.toString());
    }

    /**
     * Spec does not allow this, but we quietly parse it anyway.
     */
    @Test
    public void testSpuriousCommas() {
        AuthorizationHeader ah = AuthorizationHeader.parse("2/HMAC_SHA256(H+SHA256(E)) ,partner-id=bob, key-id=123, , signed-headers=Content-Type;X-Forwarded-For,, timestamp=140972658382 ,signature=af5938faf97a7f7a7f778af, requires-canonicalize=true, ");
        Assert.assertNotNull(ah);
        Assert.assertEquals("2/HMAC_SHA256(H+SHA256(E)) partner-id=bob, key-id=123, signed-headers=Content-Type;X-Forwarded-For, timestamp=140972658382, signature=af5938faf97a7f7a7f778af, requires-canonicalize=true", ah.toString());
    }

    /**
     * Spec does not allow this either...
     */
    @Test
    public void testEmptySignedHeaders() {
        AuthorizationHeader ah = AuthorizationHeader.parse("2/HMAC_SHA256(H+SHA256(E)) partner-id=bob, key-id=123, signed-headers=, timestamp=140972658382, signature=af5938faf97a7f7a7f778af");
        Assert.assertNotNull(ah);
        Assert.assertEquals("2/HMAC_SHA256(H+SHA256(E)) partner-id=bob, key-id=123, timestamp=140972658382, signature=af5938faf97a7f7a7f778af", ah.toString());
    }

    @Test
    public void testParseErrors() {
        String[] headers = {
                "2/HMAC_SHA256(H+SHA256(E))",
                "2/HMAC_SHA256(H+SHA256(E)) timestamp=foo"
        };
        for (String headerValue : headers) {
            try {
                AuthorizationHeader.parse(headerValue);
                Assert.fail("Parse should not succeed: " + headerValue);
            } catch (IllegalArgumentException expected) {
            }
        }
    }

    /**
     * Don't care what it does, as long as it doesn't throw or return null
     */
    @Test
    public void testEmptyToString() {
        Assert.assertNotNull(new AuthorizationHeader().toString());
    }
}
