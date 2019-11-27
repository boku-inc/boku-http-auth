package com.boku.auth.http.it;

import java.io.IOException;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.it.support.Servlets;
import com.boku.auth.http.client.BokuAPIClientResponse;
import com.boku.auth.http.client.exception.BokuAPIClientException;
import org.apache.http.client.HttpResponseException;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Tries to test server functionality in an integration environment.
 *
 * Various edge cases missing from here, although most are covered in separate unit tests.
 * If you have time, or problems crop up, please add:
 *  - invalid auth header
 *  - multiple auth headers
 *  - ts too old
 *  - signed-header
 *  - query string
 */
public class ServerTest extends CWAIntegrationTestBase {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    public ServerTest() {
        env.server.addServlet("/auth/ping", Servlets.withAuth(env.authContextProvider, new Servlets.PingHandler()));
        env.server.addServlet("/unfiltered/ping", Servlets.withAuth(env.authContextProvider, new Servlets.PingHandler()));
    }

    @Test
    public void testNoAuthHeaderSuppliedRejected() throws IOException {
        exception.expect(httpResponseException(401));
        env.client.get(url("/auth/ping")).execute();
    }

    @Test
    public void testCorrectSignatureAcceptedGET() throws IOException {
        String resp = env.client
            .get(url("/auth/ping"))
            .withAuthorization(authorization())
            .execute();
        Assert.assertEquals("GET: pong", resp);
    }

    private static AuthorizationHeader invalidAuthHeader() {
        AuthorizationHeader ah = AuthorizationHeader.parse("2/HMAC_SHA256(H+SHA256(E)) partner-id=bob, key-id=1, signed-headers=Content-Type, timestamp=1, signature=af5938faf97a7f7a7f778af");
        ah.setTimestamp(System.currentTimeMillis() / 1000);
        return ah;
    }

    @Test
    public void testIncorrectSignatureRejectedGET() throws IOException {
        exception.expect(httpResponseException(401));

        env.client
            .get(url("/auth/ping"))
            .withHeader(AuthorizationHeader.REQUEST_HEADER, invalidAuthHeader().toString())
            .execute();
    }

    @Test
    public void testCorrectSignatureAcceptedPOST() throws IOException {
        String resp = env.client
            .post(url("/auth/ping"))
            .withEntityString("Something!")
            .withAuthorization(authorization())
            .execute();
        Assert.assertEquals("POST 'Something!': pong", resp);
    }

    @Test
    public void testIncorrectSignatureRejectedPOST() throws IOException {
        exception.expect(httpResponseException(401));

        env.client
            .post(url("/auth/ping"))
            .withEntityString("Something!")
            .withHeader(AuthorizationHeader.REQUEST_HEADER, invalidAuthHeader().toString())
            .execute();
    }

    @Test
    public void testNoFilterError() throws IOException {
        try {
            env.client
                .get(url("/unfiltered/ping"))
                .withAuthorization(authorization())
                .execute();
            Assert.fail("Should not succeed");
        } catch (BokuAPIClientException ex) {
            // Client complains about no signature. Of course there isn't, since the filter isn't active
            Assert.assertEquals("Got HTTP/1.1 500 Server Error with 0 X-SignedResponse headers, expected 1!", ex.getMessage());
            // Check the underlying HTTP response to see what the server did
            BokuAPIClientResponse response = ex.getResponse();
            Assert.assertEquals(500, response.getStatusLine().getStatusCode());
            BokuAPIClientResponse.Entity entity = response.getEntity();
            Assert.assertNotNull(entity);
            Assert.assertTrue(entity.getDataAsText(), entity.getDataAsText().contains("IllegalStateException: No request context set up by filter."));
        }
    }

    private static Matcher<HttpResponseException> httpResponseException(final int status) {
        return new BaseMatcher<HttpResponseException>() {
            @Override
            public boolean matches(Object item) {
                if (item.getClass() != HttpResponseException.class) {
                    return false;
                }
                HttpResponseException ex = (HttpResponseException)item;
                return ex.getStatusCode() == status;
            }

            @Override
            public void describeTo(Description description) {
                description.appendText(HttpResponseException.class.getCanonicalName() + ": HTTP " + status);
            }
        };
    }
}
