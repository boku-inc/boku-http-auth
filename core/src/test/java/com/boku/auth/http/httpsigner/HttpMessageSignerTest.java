package com.boku.auth.http.httpsigner;

import java.security.InvalidKeyException;

import com.boku.auth.http.httpmessage.CanonicalHttpHeader;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.internal.matchers.ThrowableMessageMatcher;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.AuthorizationException;
import com.boku.auth.http.exception.AuthorizationFailedException;
import com.boku.auth.http.exception.InvalidApplicationSuppliedAuthorizationHeaderException;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.httpmessage.CanonicalHttpResponse;
import com.boku.auth.http.stringsigner.SignatureAlgorithm;
import com.boku.auth.http.stringsigner.StringSigner;

public class HttpMessageSignerTest {

    private final StringSigner mockStringSigner = Mockito.mock(StringSigner.class);

    private final HttpMessageSigner signer = new HttpMessageSigner(mockStringSigner);

    public HttpMessageSignerTest() throws InvalidKeyException {
        Mockito.when(
                mockStringSigner.generateSignature(org.mockito.Matchers.any(SignatureAlgorithm.class), org.mockito.Matchers.anyString(), org.mockito.Matchers.anyString(), org.mockito.Matchers.anyString())
        ).thenReturn("das_sig");
    }

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testHappyRequest() throws InvalidKeyException {
        AuthorizationHeader ah = getAuthorizationHeader();
        CanonicalHttpRequest httpRequest = getHttpRequest();
        signer.sign(ah, httpRequest);
        Assert.assertEquals("das_sig", ah.getSignature());

        ArgumentCaptor<String> signedStringCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(mockStringSigner).generateSignature(org.mockito.Matchers.eq(SignatureAlgorithm.HMAC_SHA256), org.mockito.Matchers.eq(ah.getPartnerId()), org.mockito.Matchers.eq(ah.getKeyId()), signedStringCaptor.capture());
        Assert.assertEquals(
                "POST /path/to/sign?foo=bar&hoge=piyo\n" +
                "Content-Type: text/html; charset=utf8\n" +
                "Accept-Language: en\n" +
                "Accept-Language: de\n" +
                "entity_digest!\n" +
                ah.getTimestamp(),
                signedStringCaptor.getValue()
        );
    }

    @Test
    public void testHappyRequestNoQstr() throws InvalidKeyException {
        AuthorizationHeader ah = getAuthorizationHeader();
        CanonicalHttpRequest httpRequest = getHttpRequest();
        httpRequest.setQueryString(null);
        signer.sign(ah, httpRequest);
        Assert.assertEquals("das_sig", ah.getSignature());

        ArgumentCaptor<String> signedStringCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(mockStringSigner).generateSignature(org.mockito.Matchers.eq(SignatureAlgorithm.HMAC_SHA256), org.mockito.Matchers.eq(ah.getPartnerId()), org.mockito.Matchers.eq(ah.getKeyId()), signedStringCaptor.capture());
        Assert.assertEquals(
                "POST /path/to/sign\n" +
                "Content-Type: text/html; charset=utf8\n" +
                "Accept-Language: en\n" +
                "Accept-Language: de\n" +
                "entity_digest!\n" +
                ah.getTimestamp(),
                signedStringCaptor.getValue()
        );
    }

    @Test
    public void testHappyRequestNoEntity() throws InvalidKeyException {
        AuthorizationHeader ah = getAuthorizationHeader();
        CanonicalHttpRequest httpRequest = getHttpRequest();
        httpRequest.setEntityDigest(null);
        signer.sign(ah, httpRequest);
        Assert.assertEquals("das_sig", ah.getSignature());

        ArgumentCaptor<String> signedStringCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(mockStringSigner).generateSignature(org.mockito.Matchers.eq(SignatureAlgorithm.HMAC_SHA256), org.mockito.Matchers.eq(ah.getPartnerId()), org.mockito.Matchers.eq(ah.getKeyId()), signedStringCaptor.capture());
        Assert.assertEquals(
                "POST /path/to/sign?foo=bar&hoge=piyo\n" +
                "Content-Type: text/html; charset=utf8\n" +
                "Accept-Language: en\n" +
                "Accept-Language: de\n" +
                "\n" +
                ah.getTimestamp(),
                signedStringCaptor.getValue()
        );
    }

    @Test
    public void testHappyResponse() throws InvalidKeyException {
        AuthorizationHeader ah = getAuthorizationHeader();
        CanonicalHttpResponse httpResponse = getHttpResponse();
        signer.sign(ah, httpResponse);
        Assert.assertEquals("das_sig", ah.getSignature());

        ArgumentCaptor<String> signedStringCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(mockStringSigner).generateSignature(org.mockito.Matchers.eq(SignatureAlgorithm.HMAC_SHA256), org.mockito.Matchers.eq(ah.getPartnerId()), org.mockito.Matchers.eq(ah.getKeyId()), signedStringCaptor.capture());
        Assert.assertEquals(
                "Content-Type: text/html; charset=utf8\n" +
                "entity_digest!\n" +
                ah.getTimestamp(),
                signedStringCaptor.getValue()
        );
    }

    @Test
    public void testUnknownScheme() {
        exception.expect(InvalidApplicationSuppliedAuthorizationHeaderException.class);
        exception.expectMessage("Failed to sign message");
        exception.expectCause(Matchers.allOf(
                Matchers.instanceOf(InvalidAuthorizationHeaderException.class),
                ThrowableMessageMatcher.hasMessage(Matchers.containsString("Unknown authorization scheme"))
        ));

        AuthorizationHeader ah = getAuthorizationHeader();
        CanonicalHttpRequest httpRequest = getHttpRequest();
        ah.setScheme("X");
        signer.sign(ah, httpRequest);
    }

    @Test
    public void testUnrecognizedKey() throws InvalidKeyException {
        exception.expect(InvalidApplicationSuppliedAuthorizationHeaderException.class);
        exception.expectMessage("Failed to sign message");
        exception.expectCause(Matchers.allOf(
                Matchers.instanceOf(InvalidAuthorizationHeaderException.class),
                ThrowableMessageMatcher.hasMessage(Matchers.containsString("Unrecognized partner-id or key-id"))
        ));

        Mockito.when(
                mockStringSigner.generateSignature(org.mockito.Matchers.any(SignatureAlgorithm.class), org.mockito.Matchers.anyString(), org.mockito.Matchers.anyString(), org.mockito.Matchers.anyString())
        ).thenThrow(new InvalidKeyException());

        AuthorizationHeader ah = getAuthorizationHeader();
        CanonicalHttpRequest httpRequest = getHttpRequest();
        signer.sign(ah, httpRequest);
    }

    @Test
    public void testVerifySuccess() throws AuthorizationException {
        AuthorizationHeader ah = getAuthorizationHeader();
        CanonicalHttpRequest httpRequest = getHttpRequest();
        signer.verifySignature(ah, httpRequest);
    }

    @Test
    public void testVerifyFailed() throws AuthorizationException {
        exception.expect(AuthorizationFailedException.class);
        exception.expectMessage("Invalid signature");

        AuthorizationHeader ah = getAuthorizationHeader();
        CanonicalHttpRequest httpRequest = getHttpRequest();
        ah.setSignature("incorrect");
        signer.verifySignature(ah, httpRequest);
    }

    private static AuthorizationHeader getAuthorizationHeader() {
        AuthorizationHeader ah = new AuthorizationHeader();
        ah.setScheme("2/HMAC_SHA256(H+SHA256(E))");
        ah.setPartnerId("bob");
        ah.setKeyId("1");
        ah.setTimestamp(System.currentTimeMillis() / 1000 - 1234); // Use a non-now time to make sure signer isn't just using the current time.
        ah.setSignature("das_sig");
        return ah;
    }

    private static CanonicalHttpRequest getHttpRequest() {
        CanonicalHttpRequest ret = new CanonicalHttpRequest();
        ret.setMethod("POST");
        ret.setPath("/path/to/sign");
        ret.setQueryString("foo=bar&hoge=piyo");
        ret.getHeaders().add(new CanonicalHttpHeader("Content-Type", "text/html; charset=utf8"));
        ret.getHeaders().add(new CanonicalHttpHeader("Accept-Language", "en"));
        ret.getHeaders().add(new CanonicalHttpHeader("Accept-Language", "de"));
        ret.setEntityDigest("entity_digest!");
        return ret;
    }

    private static CanonicalHttpResponse getHttpResponse() {
        CanonicalHttpResponse ret = new CanonicalHttpResponse();
        ret.getHeaders().add(new CanonicalHttpHeader("Content-Type", "text/html; charset=utf8"));
        ret.setEntityDigest("entity_digest!");
        return ret;
    }
}
