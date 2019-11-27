package com.boku.auth.http.it;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.it.support.Servlets;
import com.boku.auth.http.client.BokuAPIClientResponse;
import com.boku.auth.http.client.exception.BokuAPIClientException;
import com.boku.auth.http.client.exception.InvalidAPIEntityException;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpResponseException;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.boku.auth.http.it.support.HttpRequestHandler;

/**
 * Assuming the server component is working properly, test all client functionality against it.
 */
public class ClientTest extends CWAIntegrationTestBase {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    public ClientTest() {
        env.server.addServlet("/echo", Servlets.noAuth(new Servlets.EchoHandler()));
        env.server.addServlet("/auth/echo", Servlets.withAuth(env.authContextProvider, new Servlets.EchoHandler()));
        env.server.addServlet("/auth/ping", Servlets.withAuth(env.authContextProvider, new Servlets.PingHandler()));
    }

    @Test
    public void testRoundTripPOSTNoAuth() throws IOException {
        final String requestText = "five, and unicode文字列もある";
        String responseText = env.client
            .post(url("/echo?qparam=1"))
            .withHeader("X-BOKU-Test", "2")
            .withHeader("X-BOKU-Test", "3")
            .withHeader("X-BOKU-Something", "4")
            .withEntityString(requestText)
            .execute();

        Assert.assertEquals(
            "POST /echo?qparam=1\n" +
            "Content-Type: text/plain; charset=UTF-8\n" +
            "X-BOKU-Something: 4\n" +
            "X-BOKU-Test: 2\n" +
            "X-BOKU-Test: 3\n" +
            "\n" +
            requestText,
            responseText
        );
    }

    @Test
    public void testRoundTripPOSTWithAuth() throws IOException {
        String requestText = "five, and unicode文字列もある";
        String responseText = env.client
            .post(url("/auth/echo?qparam=1"))
            .withAuthorization(authorization("X-BOKU-Test", "X-DoesntExist"))
            .withHeader("X-BOKU-Test", "2")
            .withHeader("X-boku-test", "3")
            .withHeader("X-BOKU-Something", "4")
            .withEntityString(requestText)
            .execute();

        Assert.assertNotNull(responseText);
        Assert.assertEquals(
            "POST /auth/echo?qparam=1\n" +
            "Authorization: auth contents\n" +
            "Content-Type: text/plain; charset=UTF-8\n" +
            "X-BOKU-Something: 4\n" +
            "X-BOKU-Test: 2\n" +
            "X-BOKU-Test: 3\n" +
            "\n" +
            requestText,
            responseText.replaceFirst("Authorization: [^\n]+", "Authorization: auth contents")
        );
    }

    @Test
    public void testGET() throws IOException {
        String responseText = env.client
            .get(url("/auth/ping"))
            .withAuthorization(authorization())
            .execute();
        Assert.assertEquals("GET: pong", responseText);
    }

    @Test
    public void testPUT() throws IOException {
        String responseText = env.client
            .put(url("/auth/ping"))
            .withAuthorization(authorization())
            .withEntityString("putty")
            .execute();
        Assert.assertEquals("PUT 'putty': pong", responseText);
    }

    @Test
    public void testDELETE() throws IOException {
        String responseText = env.client
            .delete(url("/auth/ping"))
            .withAuthorization(authorization())
            .execute();
        Assert.assertEquals("DELETE: pong", responseText);
    }

    @Test
    public void testNoSignatureReturned() throws IOException {
        env.server.addServlet("/no-signature", Servlets.noAuth(new Servlets.PingHandler()));

        exception.expect(BokuAPIClientException.class);
        exception.expectMessage(Matchers.containsString("Got HTTP/1.1 200 OK with 0 X-SignedResponse headers, expected 1!"));

        env.client
            .get(url("/no-signature"))
            .withAuthorization(authorization())
            .execute();
    }

    @Test
    public void testInvalidSignatureReturned() throws IOException {
        env.server.addServlet("/invalid-signature", Servlets.noAuth(
                new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        new Servlets.PingHandler().handle(req, resp, requestEntity);
                        AuthorizationHeader ah = AuthorizationHeader.parse(req.getHeader(AuthorizationHeader.REQUEST_HEADER));
                        resp.setHeader(AuthorizationHeader.RESPONSE_HEADER, ah.toString());
                    }
                }
            ));

        exception.expect(BokuAPIClientException.class);
        exception.expectMessage(Matchers.containsString("Failed to verify signature of HTTP/1.1 200 OK response"));

        env.client
            .get(url("/invalid-signature"))
            .withAuthorization(authorization())
            .execute();
    }

    @Test
    public void testServerReturnsMojibake() throws IOException {
        final String text = "僕は文字化けになりたくないんだよぉ〜！";
        final byte[] sjis = text.getBytes("shift-jis");
        final String garbled = new String(sjis, StandardCharsets.UTF_8); // This is where parts of the SJIS data get lost

        // Check that our input is actually lossy
        {
            String mojibake = new String(garbled.getBytes(StandardCharsets.UTF_8), "shift-jis");
            Assert.assertNotEquals(text, mojibake);
        }

        env.server.addServlet("/auth/mojibake", Servlets.noAuth(
            new HttpRequestHandler() {
                @Override
                public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                    resp.setHeader("Content-Type", "text/plain; charset=UTF-8");
                    resp.getOutputStream().write(sjis);
                }
            }
        ));

        String result = env.client
            .get(url("/auth/mojibake"))
            .withAuthorization(authorization())
            .execute();

        // Garbled, but auth should have no problem
        Assert.assertEquals(new String(sjis, StandardCharsets.UTF_8), result);
    }

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    private static class X {
        String a;
        String b;
    }

    @Test
    public void testMarshalling() throws IOException {
        X x = new X();
        x.a = "foo";
        x.b = "bar";

        String responseText = env.client
            .post(url("/auth/echo"))
            .withHeader("X-BOKU-Test", "2")
            .withAuthorization(authorization())
            .withEntity(x)
            .execute();

        Assert.assertNotNull(responseText);
        Assert.assertEquals(
            "POST /auth/echo\n" +
            "Authorization: auth contents\n" +
            "Content-Type: application/xml; charset=\"UTF-8\"\n" +
            "X-BOKU-Test: 2\n" +
            "\n" +
            "<x><a>foo</a><b>bar</b></x>",
            responseText.replaceFirst("Authorization: [^\n]+", "Authorization: auth contents")
        );
    }

    @Test
    public void testUnmarshalling() throws IOException {
        env.server.addServlet("/auth/json", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.setContentType("application/json; charset=UTF-8");
                        resp.getOutputStream().print("<x><a>foo</a><b>bar</b></x>");
                    }
                }
            ));

        X x = env.client.get(url("/auth/json"))
            .withAuthorization(authorization())
            .execute(X.class);
        Assert.assertNotNull(x);
        Assert.assertEquals("foo", x.a);
        Assert.assertEquals("bar", x.b);
    }

    @Test
    public void testUnmarshalFails() throws IOException {
        env.server.addServlet("/auth/json", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.setContentType("application/json; charset=UTF-8");
                        resp.getOutputStream().print("this is not xml!");
                    }
                }
            ));

        exception.expect(InvalidAPIEntityException.class);

        env.client.get(url("/auth/json"))
            .withAuthorization(authorization())
            .execute(X.class);
    }

    @Test
    public void testRawResponseEntity() throws IOException {
        BokuAPIClientResponse response = env.client
            .post(url("/auth/ping"))
            .withAuthorization(authorization())
            .withEntityString("test")
            .execute(BokuAPIClientResponse.class);
        Assert.assertNotNull(response);
        BokuAPIClientResponse.Entity entity = response.getEntity();
        Assert.assertNotNull(entity);
        Assert.assertEquals("text/plain", entity.getContentType().getMimeType());
        Assert.assertNotNull(entity.getCharset());
        Assert.assertEquals("UTF-8", entity.getCharset().name());
        String expectedString = "POST 'test': pong";
        Assert.assertArrayEquals(expectedString.getBytes(entity.getCharset()), entity.getData());
        Assert.assertEquals(expectedString, entity.getDataAsText());
    }

    @Test
    public void testNoCharsetAuthSucceeds() throws IOException {
        env.server.addServlet("/auth/broken", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.getOutputStream().write(new byte[]{(byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD});
                    }
                }
            ));
        BokuAPIClientResponse response = env.client
            .get(url("/auth/broken"))
            .withAuthorization(authorization())
            .execute(BokuAPIClientResponse.class);
        Assert.assertNotNull(response);
        BokuAPIClientResponse.Entity entity = response.getEntity();
        Assert.assertNotNull(entity);
        Assert.assertEquals("application/octet-stream", entity.getContentType().getMimeType());
        Assert.assertArrayEquals(new byte[]{(byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD}, entity.getData());
    }

    @Test
    public void testNoCharsetDefaultsUTF8() throws IOException {
        env.server.addServlet("/auth/broken", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.setContentType("text/plain");
                        resp.getOutputStream().write("This is a test! これはテスト！".getBytes(StandardCharsets.UTF_8));
                    }
                }
            ));

        BokuAPIClientResponse response = env.client
            .get(url("/auth/broken"))
            .withAuthorization(authorization())
            .execute(BokuAPIClientResponse.class);
        Assert.assertEquals("text/plain", response.getEntity().getContentType().toString());
        Assert.assertEquals("This is a test! これはテスト！", response.getEntity().getDataAsText());
    }

    @Test
    public void testAlternateCharsetWorks() throws IOException {
        final String altCharset = "shift-jis";
        final String respText = "sjisテスト";

        env.server.addServlet("/auth/altcharset", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.setContentType("text/plain; charset=" + altCharset);
                        resp.getOutputStream().write(respText.getBytes(altCharset));
                    }
                }
            ));

        String response = env.client
            .get(url("/auth/altcharset"))
            .withAuthorization(authorization())
            .execute();
        Assert.assertEquals(respText, response);
    }

    @Test
    public void testNoResponseEntity() throws IOException {
        env.server.addServlet("/auth/no-entity", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) {
                        resp.setStatus(HttpStatus.SC_NO_CONTENT);
                    }
                }
            ));

        env.server.addServlet("/auth/zero-entity", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) {
                    }
                }
            ));

        // No entity
        Assert.assertNull(
            env.client
                .get(url("/auth/no-entity"))
                .withAuthorization(authorization())
                .execute()
        );

        // No entity using BokuAPIClientResponse
        BokuAPIClientResponse response = env.client
            .get(url("/auth/no-entity"))
            .withAuthorization(authorization())
            .execute(BokuAPIClientResponse.class);
        Assert.assertNotNull(response);
        Assert.assertNull(response.getEntity());

        // Zero-length entity
        response = env.client
            .get(url("/auth/zero-entity"))
            .withAuthorization(authorization())
            .execute(BokuAPIClientResponse.class);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getEntity());
        Assert.assertEquals(0, response.getEntity().getData().length);
    }

    @Test
    public void testHTTP500() throws IOException {
        env.server.addServlet("/auth/error", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.setStatus(HttpStatus.SC_INTERNAL_SERVER_ERROR);
                        resp.setContentType("text/plain; charset=UTF-8");
                        resp.getOutputStream().print("Ohnoes");
                    }
                }
            ));

        exception.expect(HttpResponseException.class);
        exception.expectMessage("HTTP/1.1 500 Server Error: text/plain; charset=UTF-8[Ohnoes]");

        env.client
            .get(url("/auth/error"))
            .withAuthorization(authorization())
            .execute();
    }

    @Test
    public void testHTTP301() throws IOException {
        env.server.addServlet("/auth/redirect", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.setStatus(HttpStatus.SC_MOVED_PERMANENTLY);
                        resp.setHeader("Location", "/auth/somewhereelse");
                        resp.setContentType("text/plain; charset=UTF-8");
                        resp.getOutputStream().print("Moved!");
                    }
                }
            ));

        exception.expect(HttpResponseException.class);
        exception.expectMessage("HTTP/1.1 301 Moved Permanently: text/plain; charset=UTF-8[Moved!]");

        env.client
            .get(url("/auth/redirect"))
            .withAuthorization(authorization())
            .execute();
    }

    @Test
    public void testHTTPErrorAPIResponse() throws IOException {
        env.server.addServlet("/auth/conflict", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.setStatus(HttpStatus.SC_CONFLICT);
                        resp.setContentType("application/json; charset=UTF-8");
                        resp.getOutputStream().print("<x><a>foo</a><b>bar</b></x>");
                    }
                }
            ));

        BokuAPIClientResponse response = env.client
            .get(url("/auth/conflict"))
            .withAuthorization(authorization())
            .execute(BokuAPIClientResponse.class);

        Assert.assertNotNull(response);
        Assert.assertEquals(409, response.getStatusLine().getStatusCode());

        BokuAPIClientResponse.Entity entity = response.getEntity();
        Assert.assertNotNull(entity);
        Assert.assertEquals("<x><a>foo</a><b>bar</b></x>", entity.getDataAsText());
        X x = entity.getDataAs(X.class);
        Assert.assertNotNull(x);
        Assert.assertEquals("foo", x.a);
        Assert.assertEquals("bar", x.b);
    }

    @Test
    public void testHeaders() throws IOException {
        env.server.addServlet("/auth/headers", Servlets.withAuth(
                env.authContextProvider, new HttpRequestHandler() {
                    @Override
                    public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
                        resp.setStatus(HttpStatus.SC_NO_CONTENT);
                        resp.addHeader("X-BOKU-Test", "1");
                        resp.addHeader("X-BOKU-Test", "2");
                        resp.addHeader("X-BOKU-Something", "3");
                    }
                }
            ));

        BokuAPIClientResponse response = env.client
            .get(url("/auth/headers"))
            .withAuthorization(authorization())
            .execute(BokuAPIClientResponse.class);
        Assert.assertNotNull(response);

        assertHeader(response, "X-BOKU-Test", 2, "1", "2");
        assertHeader(response, "X-BOKU-Something", 1, "3", "3");

        Assert.assertFalse(response.containsHeader("X-Nothing"));
        Assert.assertEquals(0, response.getHeaders("X-Nothing").length);
        Assert.assertNull(response.getFirstHeader("X-Nothing"));
        Assert.assertNull(response.getLastHeader("X-Nothing"));

        Assert.assertNotNull(response.getAllHeaders());
        Assert.assertTrue(response.getAllHeaders().length >= 3);
    }

    private static void assertHeader(BokuAPIClientResponse response, String header, int count, String first, String last) {
        String[] variants = new String[] {
            header, header.toUpperCase(), header.toLowerCase()
        };
        for (String variant : variants) {
            Assert.assertTrue(variant, response.containsHeader(variant));
            Assert.assertEquals(variant, count, response.getHeaders(variant).length);
            Assert.assertEquals(variant, first, response.getFirstHeader(variant).getValue());
            Assert.assertEquals(variant, last, response.getLastHeader(variant).getValue());
        }
    }
}
