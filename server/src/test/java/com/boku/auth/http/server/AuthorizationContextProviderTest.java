package com.boku.auth.http.server;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.AuthorizationException;
import com.boku.auth.http.exception.AuthorizationFailedException;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.boku.auth.http.server.spi.CurrentRequestAuthInfo;
import com.boku.auth.http.server.spi.CurrentRequestAuthInfoFactory;

public class AuthorizationContextProviderTest {

    private final CurrentRequestAuthInfoFactory mockRequestInfoFactory = Mockito.mock(CurrentRequestAuthInfoFactory.class);
    private final HttpMessageSigner mockHttpMessageSigner = Mockito.mock(HttpMessageSigner.class);

    private final AuthorizationContextProvider contextProvider = new AuthorizationContextProvider(this.mockRequestInfoFactory, this.mockHttpMessageSigner);

    public AuthorizationContextProviderTest() throws AuthorizationException {
        final String validSignature = getValidCurrentRequestAuthInfo().getAuthorizationHeader().getSignature();
        Mockito.doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocation) throws Exception {
                AuthorizationHeader ah = (AuthorizationHeader)invocation.getArguments()[0];
                if (!validSignature.equals(ah.getSignature())) {
                    throw new AuthorizationFailedException("Invalid signature");
                }
                return null;
            }
        }).when(mockHttpMessageSigner).verifySignature(Matchers.any(AuthorizationHeader.class), Matchers.any(CanonicalHttpRequest.class));
    }

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testHappy() throws AuthorizationException {
        Mockito.when(mockRequestInfoFactory.getCurrentRequestInfo()).thenReturn(getValidCurrentRequestAuthInfo());
        AuthorizationContext ac = contextProvider.get();
        Assert.assertNotNull(ac);
        ac.assertValidForPartner("bob");
    }

    @Test
    public void testInvalidRequestInfo() throws AuthorizationException {
        InvalidAuthorizationHeaderException thrown = new InvalidAuthorizationHeaderException("moo");
        Mockito.when(mockRequestInfoFactory.getCurrentRequestInfo()).thenThrow(thrown);
        try {
            contextProvider.get();
            Assert.fail("get() should not succeed");
        } catch (InvalidAuthorizationHeaderException ex) {
            Assert.assertSame(thrown, ex);
        }
    }

    @Test
    public void testInvalidAuthorizationHeader() throws AuthorizationException {
        exception.expect(InvalidAuthorizationHeaderException.class);
        exception.expectMessage("Invalid Authorization header: scheme: may not be null; signature: may not be null");

        CurrentRequestAuthInfo ri = getValidCurrentRequestAuthInfo();
        ri.getAuthorizationHeader().setScheme(null);
        ri.getAuthorizationHeader().setSignature(null);
        Mockito.when(mockRequestInfoFactory.getCurrentRequestInfo()).thenReturn(ri);

        contextProvider.get();
    }

    @Test
    public void testTimestampOld() throws AuthorizationException {
        exception.expect(AuthorizationFailedException.class);
        exception.expectMessage("Signature expired");

        CurrentRequestAuthInfo ri = getValidCurrentRequestAuthInfo();
        ri.getAuthorizationHeader().setTimestamp(ri.getAuthorizationHeader().getTimestamp() - 600);
        Mockito.when(mockRequestInfoFactory.getCurrentRequestInfo()).thenReturn(ri);

        contextProvider.get();
    }

    @Test
    public void testTimestampFuture() throws AuthorizationException {
        exception.expect(AuthorizationFailedException.class);
        exception.expectMessage("Signature expired");

        CurrentRequestAuthInfo ri = getValidCurrentRequestAuthInfo();
        ri.getAuthorizationHeader().setTimestamp(ri.getAuthorizationHeader().getTimestamp() + 600);
        Mockito.when(mockRequestInfoFactory.getCurrentRequestInfo()).thenReturn(ri);

        contextProvider.get();
    }

    @Test
    public void testSigVerifyFailed() throws AuthorizationException {
        exception.expect(AuthorizationFailedException.class);
        exception.expectMessage("Invalid signature");

        CurrentRequestAuthInfo ri = getValidCurrentRequestAuthInfo();
        ri.getAuthorizationHeader().setSignature("invalid");
        Mockito.when(mockRequestInfoFactory.getCurrentRequestInfo()).thenReturn(ri);

        contextProvider.get();
    }

    private static CurrentRequestAuthInfo getValidCurrentRequestAuthInfo() {
        AuthorizationHeader ah = new AuthorizationHeader();
        ah.setScheme("TEST");
        ah.setPartnerId("bob");
        ah.setKeyId("1");
        ah.setTimestamp(System.currentTimeMillis() / 1000);
        ah.setSignature("VALID_SIGNATURE");

        CanonicalHttpRequest cr = new CanonicalHttpRequest();
        cr.setMethod("POST");
        cr.setPath("/test/path");
        cr.setEntityDigest("SOME_DIGEST");

        return new CurrentRequestAuthInfo(ah, cr);
    }
}
