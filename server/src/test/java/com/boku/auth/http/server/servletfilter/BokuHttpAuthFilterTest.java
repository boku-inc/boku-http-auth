package com.boku.auth.http.server.servletfilter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.concurrent.atomic.AtomicReference;

import javax.servlet.FilterChain;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.InvalidApplicationSuppliedAuthorizationHeaderException;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.httpmessage.CanonicalHttpHeader;
import com.boku.auth.http.httpmessage.CanonicalHttpMessage;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.util.DigestFactory;
import com.boku.util.HexCodec;
import com.boku.util.IO;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.boku.auth.http.server.spi.CurrentRequestAuthInfo;

public class BokuHttpAuthFilterTest {

    private final HttpMessageSigner mockHttpMessageSigner = Mockito.mock(HttpMessageSigner.class);

    private final ThreadLocalServletRequestContextHolder threadLocalServletRequestContextHolder = new ThreadLocalServletRequestContextHolder();

    private final BokuHttpAuthFilter filter = new BokuHttpAuthFilter(
            threadLocalServletRequestContextHolder,
            mockHttpMessageSigner
    );

    private final BokuHttpAuthFilterCurrentRequestAuthInfoFactory currentRequestAuthInfoFactory = new BokuHttpAuthFilterCurrentRequestAuthInfoFactory(threadLocalServletRequestContextHolder);

    public BokuHttpAuthFilterTest() {
        Mockito.doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocation) {
                AuthorizationHeader ah = (AuthorizationHeader)invocation.getArguments()[0];
                ah.setScheme(HttpMessageSigner.SCHEME);
                ah.setTimestamp(System.currentTimeMillis() / 1000);
                ah.setSignature("das_sig");
                return null;
            }
        })
            .when(mockHttpMessageSigner)
            .sign(org.mockito.Matchers.any(AuthorizationHeader.class), org.mockito.Matchers.any(CanonicalHttpMessage.class));
    }

    private void assertNoCurrentRequest() throws InvalidAuthorizationHeaderException {
        try {
            currentRequestAuthInfoFactory.getCurrentRequestInfo();
            Assert.fail("currentRequestAuthInfoFactory should not return anything!");
        } catch (IllegalStateException expected) {
            Assert.assertThat(expected.getMessage(), Matchers.containsString("No request context set up by filter"));
        }
    }

    @Test
    public void testNoAuth() throws IOException, ServletException, InvalidAuthorizationHeaderException {
        HttpServletRequest request = getServletRequest();
        HttpServletResponse response = getServletResponse();

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) {
                receivedRequest.set(request);
                receivedResponse.set(response);

                try {
                    currentRequestAuthInfoFactory.getCurrentRequestInfo();
                    Assert.fail("getCurrentRequestInfo should complain about lack of Authorization header");
                } catch (InvalidAuthorizationHeaderException expected) {
                }
            }
        });

        Assert.assertSame(request, receivedRequest.get());
        Assert.assertSame(response, receivedResponse.get());

        assertNoCurrentRequest();
    }

    @Test
    public void testNoAuthThrows() throws IOException, ServletException, InvalidAuthorizationHeaderException {
        HttpServletRequest request = getServletRequest();
        HttpServletResponse response = getServletResponse();

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        final IllegalStateException toThrow = new IllegalStateException();
        try {
            filter.doFilter(request, response, new FilterChain() {
                @Override
                public void doFilter(ServletRequest request, ServletResponse response) {
                    receivedRequest.set(request);
                    receivedResponse.set(response);
                    throw toThrow;
                }
            });
            Assert.fail("Filter should surface exceptions");
        } catch (IllegalStateException expected) {
            Assert.assertSame(toThrow, expected);
        }

        Assert.assertSame(request, receivedRequest.get());
        Assert.assertSame(response, receivedResponse.get());

        assertNoCurrentRequest();
    }

    @Test
    public void testHappy() throws InvalidAuthorizationHeaderException, IOException, ServletException {
        final String method = "POST";
        final String path = "/fake/path";
        final String qstr = "foo=bar&hoge=hoge";
        final String entityText = "the entity";
        HttpServletRequest request = getServletRequest(method, path, qstr, entityText);

        provideHeaders(request, "Authorization", "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type");
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                String requestText = streamToString(request.getInputStream());
                Assert.assertEquals(entityText, requestText);

                CurrentRequestAuthInfo ri;
                try {
                    ri = currentRequestAuthInfoFactory.getCurrentRequestInfo();
                } catch (InvalidAuthorizationHeaderException ex) {
                    throw new AssertionError(ex);
                }
                Assert.assertNotNull(ri);

                Assert.assertNotNull(ri.getAuthorizationHeader());
                Assert.assertEquals("test", ri.getAuthorizationHeader().getScheme());
                Assert.assertEquals("aaa", ri.getAuthorizationHeader().getSignature());

                Assert.assertNotNull(ri.getCanonicalRequest());
                Assert.assertEquals(method, ri.getCanonicalRequest().getMethod());
                Assert.assertEquals(path, ri.getCanonicalRequest().getPath());
                Assert.assertEquals(qstr, ri.getCanonicalRequest().getQueryString());
                Assert.assertEquals(1, ri.getCanonicalRequest().getHeaders().size());
                Assert.assertEquals("Content-Type", ri.getCanonicalRequest().getHeaders().get(0).getName());
                Assert.assertEquals("text/plain", ri.getCanonicalRequest().getHeaders().get(0).getValue());

                Assert.assertEquals(sha256Hex(entityText), ri.getCanonicalRequest().getEntityDigest());

                HttpServletResponse httpResponse = (HttpServletResponse)response;
                httpResponse.setHeader("Content-Type", "text/fancy");
                response.getOutputStream().write("a response".getBytes(StandardCharsets.UTF_8));
            }
        });

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("a response", new String(outputStreamCapture.toByteArray()));

        ArgumentCaptor<String> respHeaderCapture = ArgumentCaptor.forClass(String.class);
        Mockito.verify(response).setHeader(org.mockito.Matchers.eq("X-SignedResponse"), respHeaderCapture.capture());
        AuthorizationHeader ah = AuthorizationHeader.parse(respHeaderCapture.getValue());
        Assert.assertEquals("2/HMAC_SHA256(H+SHA256(E))", ah.getScheme());
        Assert.assertEquals("a", ah.getPartnerId());
        Assert.assertEquals("b", ah.getKeyId());
        Assert.assertNotNull(ah.getTimestamp());
        Assert.assertEquals("das_sig", ah.getSignature());

        ArgumentCaptor<CanonicalHttpMessage> signedMessageCaptor = ArgumentCaptor.forClass(CanonicalHttpMessage.class);
        Mockito.verify(this.mockHttpMessageSigner).sign(org.mockito.Matchers.any(AuthorizationHeader.class), signedMessageCaptor.capture());
        CanonicalHttpMessage httpResponse = signedMessageCaptor.getValue();
        Assert.assertNotNull(httpResponse);
        Assert.assertEquals(sha256Hex("a response"), httpResponse.getEntityDigest());
        Assert.assertEquals(Collections.singletonList(new CanonicalHttpHeader("Content-Type", "text/fancy")), httpResponse.getHeaders());
    }

    @Test
    public void testHappy_getCurrentRequestInfoCalledMoreThanOnce() throws InvalidAuthorizationHeaderException, IOException, ServletException {
        final String method = "POST";
        final String path = "/fake/path";
        final String qstr = "foo=bar&hoge=hoge";
        final String entityText = "the entity";
        HttpServletRequest request = getServletRequest(method, path, qstr, entityText);

        provideHeaders(request, "Authorization", "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type");
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();
        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                String requestText = streamToString(request.getInputStream());
                Assert.assertEquals(entityText, requestText);

                CurrentRequestAuthInfo ri;
                try {
                    // Call getCurrentRequestInfo() multiple times to make sure EntityDigest != null after the first call
                    currentRequestAuthInfoFactory.getCurrentRequestInfo();
                    currentRequestAuthInfoFactory.getCurrentRequestInfo();
                    ri = currentRequestAuthInfoFactory.getCurrentRequestInfo();
                } catch (InvalidAuthorizationHeaderException ex) {
                    throw new AssertionError(ex);
                }
                Assert.assertNotNull(ri);
                Assert.assertNotNull(ri.getCanonicalRequest());
                Assert.assertEquals(sha256Hex(entityText), ri.getCanonicalRequest().getEntityDigest());
            }
        });
        assertNoCurrentRequest();
    }

    @Test
    public void testAuthedThrows() throws InvalidAuthorizationHeaderException, IOException, ServletException {
        HttpServletRequest request = getServletRequest();

        provideHeaders(request, "Authorization", "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type");
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        final IllegalStateException toThrow = new IllegalStateException();
        try {
            filter.doFilter(request, response, new FilterChain() {
                @Override
                public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                    receivedRequest.set(request);
                    receivedResponse.set(response);

                    streamToString(request.getInputStream());

                    CurrentRequestAuthInfo ri;
                    try {
                        ri = currentRequestAuthInfoFactory.getCurrentRequestInfo();
                    } catch (InvalidAuthorizationHeaderException ex) {
                        throw new AssertionError(ex);
                    }
                    Assert.assertNotNull(ri);

                    throw toThrow;
                }
            });
            Assert.fail("Exception should not be swallowed");
        } catch (IllegalStateException ex) {
            Assert.assertSame(toThrow, ex);
        }

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("", new String(outputStreamCapture.toByteArray()));

        Mockito.verifyNoMoreInteractions(response);
    }

    @Test
    public void testNoAccess() throws InvalidAuthorizationHeaderException, IOException, ServletException {
        HttpServletRequest request = getServletRequest();

        provideHeaders(request, "Authorization", "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type");
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                streamToString(request.getInputStream());

                response.getOutputStream().write("a response".getBytes(StandardCharsets.UTF_8));
            }
        });

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("a response", new String(outputStreamCapture.toByteArray()));

        ArgumentCaptor<String> respHeaderCapture = ArgumentCaptor.forClass(String.class);
        Mockito.verify(response).setHeader(org.mockito.Matchers.eq("X-SignedResponse"), respHeaderCapture.capture());
        AuthorizationHeader ah = AuthorizationHeader.parse(respHeaderCapture.getValue());
        Assert.assertEquals("2/HMAC_SHA256(H+SHA256(E))", ah.getScheme());
        Assert.assertEquals("a", ah.getPartnerId());
        Assert.assertEquals("b", ah.getKeyId());
        Assert.assertNotNull(ah.getTimestamp());
        Assert.assertEquals("das_sig", ah.getSignature());
    }

    @Test
    public void testInvalidAuthHeader() throws IOException, ServletException, InvalidAuthorizationHeaderException {
        HttpServletRequest request = getServletRequest();

        provideHeaders(request, "Authorization", "test");
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                streamToString(request.getInputStream());

                try {
                    currentRequestAuthInfoFactory.getCurrentRequestInfo();
                    Assert.fail("Should not be able to get request info");
                } catch (InvalidAuthorizationHeaderException expected) {
                    Assert.assertThat(expected.getMessage(), Matchers.containsString("format invalid"));
                }

                response.getOutputStream().write("a response".getBytes(StandardCharsets.UTF_8));
            }
        });

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("a response", new String(outputStreamCapture.toByteArray()));

        Mockito.verify(response).getOutputStream();
        Mockito.verifyNoMoreInteractions(response);
    }

    @Test
    public void testMultipleAuthHeaders() throws IOException, ServletException, InvalidAuthorizationHeaderException {
        HttpServletRequest request = getServletRequest();

        provideHeaders(request, "Authorization",
                "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type",
                "test partner-id=a, key-id=b, signature=yyy, signed-headers=Content-Type"
        );
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                streamToString(request.getInputStream());

                try {
                    currentRequestAuthInfoFactory.getCurrentRequestInfo();
                    Assert.fail("Should not be able to get request info");
                } catch (InvalidAuthorizationHeaderException expected) {
                    Assert.assertThat(expected.getMessage(), Matchers.containsString("Multiple Authorization headers provided"));
                }

                response.getOutputStream().write("a response".getBytes(StandardCharsets.UTF_8));
            }
        });

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("a response", new String(outputStreamCapture.toByteArray()));

        Mockito.verify(response).getOutputStream();
        Mockito.verifyNoMoreInteractions(response);
    }

    @Test
    public void testResponseSignerThrows() throws IOException, ServletException, InvalidAuthorizationHeaderException {
        Mockito.doThrow(
                new InvalidApplicationSuppliedAuthorizationHeaderException("Failed to sign message", new InvalidAuthorizationHeaderException("Unrecognized partner-id"))
        )
            .when(this.mockHttpMessageSigner)
            .sign(org.mockito.Matchers.any(AuthorizationHeader.class), org.mockito.Matchers.any(CanonicalHttpMessage.class));

        HttpServletRequest request = getServletRequest();

        provideHeaders(request, "Authorization", "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type");
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                streamToString(request.getInputStream());

                CurrentRequestAuthInfo ri;
                try {
                    ri = currentRequestAuthInfoFactory.getCurrentRequestInfo();
                } catch (InvalidAuthorizationHeaderException ex) {
                    throw new AssertionError(ex);
                }
                Assert.assertNotNull(ri);

                response.getOutputStream().write("a response".getBytes(StandardCharsets.UTF_8));
            }
        });

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("a response", new String(outputStreamCapture.toByteArray()));

        Mockito.verify(response).getOutputStream();
        Mockito.verify(response).getHeaders("Content-Type");

        // Should not call setHeader
        Mockito.verifyNoMoreInteractions(response);
    }

    @Test
    public void testMissingSignedHeader() throws IOException, ServletException, InvalidAuthorizationHeaderException {
        HttpServletRequest request = getServletRequest();

        provideHeaders(request, "Authorization", "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                streamToString(request.getInputStream());

                try {
                    currentRequestAuthInfoFactory.getCurrentRequestInfo();
                    Assert.fail("Should not be able to get request info");
                } catch (InvalidAuthorizationHeaderException expected) {
                    Assert.assertThat(expected.getMessage(), Matchers.containsString("signed-headers specified Content-Type, but was not found"));
                }

                response.getOutputStream().write("a response".getBytes(StandardCharsets.UTF_8));
            }
        });

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("a response", new String(outputStreamCapture.toByteArray()));

        ArgumentCaptor<String> respHeaderCapture = ArgumentCaptor.forClass(String.class);
        Mockito.verify(response).setHeader(org.mockito.Matchers.eq("X-SignedResponse"), respHeaderCapture.capture());
        AuthorizationHeader ah = AuthorizationHeader.parse(respHeaderCapture.getValue());
        Assert.assertEquals("2/HMAC_SHA256(H+SHA256(E))", ah.getScheme());
        Assert.assertEquals("a", ah.getPartnerId());
        Assert.assertEquals("b", ah.getKeyId());
        Assert.assertNotNull(ah.getTimestamp());
        Assert.assertEquals("das_sig", ah.getSignature());

    }

    @Test
    public void testNoRequestEntity() throws IOException, ServletException, InvalidAuthorizationHeaderException {
        final String method = "GET";
        final String path = "/fake/path";
        final String qstr = "foo=bar&hoge=hoge";
        HttpServletRequest request = getServletRequest(method, path, qstr, null);

        provideHeaders(request, "Authorization", "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type");
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                String requestText = streamToString(request.getInputStream());
                Assert.assertEquals("", requestText);

                CurrentRequestAuthInfo ri;
                try {
                    ri = currentRequestAuthInfoFactory.getCurrentRequestInfo();
                } catch (InvalidAuthorizationHeaderException ex) {
                    throw new AssertionError(ex);
                }
                Assert.assertNotNull(ri);

                Assert.assertNotNull(ri.getAuthorizationHeader());
                Assert.assertEquals("test", ri.getAuthorizationHeader().getScheme());
                Assert.assertEquals("aaa", ri.getAuthorizationHeader().getSignature());

                Assert.assertNotNull(ri.getCanonicalRequest());
                Assert.assertEquals(method, ri.getCanonicalRequest().getMethod());
                Assert.assertEquals(path, ri.getCanonicalRequest().getPath());
                Assert.assertEquals(qstr, ri.getCanonicalRequest().getQueryString());
                Assert.assertEquals(1, ri.getCanonicalRequest().getHeaders().size());
                Assert.assertEquals("Content-Type", ri.getCanonicalRequest().getHeaders().get(0).getName());
                Assert.assertEquals("text/plain", ri.getCanonicalRequest().getHeaders().get(0).getValue());

                Assert.assertNull(ri.getCanonicalRequest().getEntityDigest());

                HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.setHeader("Content-Type", "text/fancy");
                response.getOutputStream().write("a response".getBytes(StandardCharsets.UTF_8));
            }
        });

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("a response", new String(outputStreamCapture.toByteArray()));

        ArgumentCaptor<String> respHeaderCapture = ArgumentCaptor.forClass(String.class);
        Mockito.verify(response).setHeader(org.mockito.Matchers.eq("X-SignedResponse"), respHeaderCapture.capture());
        AuthorizationHeader ah = AuthorizationHeader.parse(respHeaderCapture.getValue());
        Assert.assertEquals("2/HMAC_SHA256(H+SHA256(E))", ah.getScheme());
        Assert.assertEquals("a", ah.getPartnerId());
        Assert.assertEquals("b", ah.getKeyId());
        Assert.assertNotNull(ah.getTimestamp());
        Assert.assertEquals("das_sig", ah.getSignature());
    }

    @Test
    public void testNoResponseEntity() throws IOException, ServletException, InvalidAuthorizationHeaderException {
        HttpServletRequest request = getServletRequest();

        provideHeaders(request, "Authorization", "test partner-id=a, key-id=b, signature=aaa, signed-headers=Content-Type");
        provideHeaders(request, "Content-Type", "text/plain");

        ByteArrayOutputStream outputStreamCapture = new ByteArrayOutputStream();
        HttpServletResponse response = getServletResponse(outputStreamCapture);

        final AtomicReference<Object> receivedRequest = new AtomicReference<>();
        final AtomicReference<Object> receivedResponse = new AtomicReference<>();

        assertNoCurrentRequest();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
                receivedRequest.set(request);
                receivedResponse.set(response);

                streamToString(request.getInputStream());

                CurrentRequestAuthInfo ri;
                try {
                    ri = currentRequestAuthInfoFactory.getCurrentRequestInfo();
                } catch (InvalidAuthorizationHeaderException ex) {
                    throw new AssertionError(ex);
                }
                Assert.assertNotNull(ri);

                Assert.assertNotNull(ri.getAuthorizationHeader());
                Assert.assertEquals("test", ri.getAuthorizationHeader().getScheme());
                Assert.assertEquals("aaa", ri.getAuthorizationHeader().getSignature());

                Assert.assertNotNull(ri.getCanonicalRequest());
                Assert.assertNotNull(ri.getCanonicalRequest().getEntityDigest());

                // No response written
            }
        });

        assertNoCurrentRequest();

        Assert.assertNotNull(receivedRequest.get());
        Assert.assertNotNull(receivedResponse.get());

        Assert.assertEquals("", new String(outputStreamCapture.toByteArray()));

        ArgumentCaptor<String> respHeaderCapture = ArgumentCaptor.forClass(String.class);
        Mockito.verify(response).setHeader(org.mockito.Matchers.eq("X-SignedResponse"), respHeaderCapture.capture());
        AuthorizationHeader ah = AuthorizationHeader.parse(respHeaderCapture.getValue());
        Assert.assertEquals("2/HMAC_SHA256(H+SHA256(E))", ah.getScheme());
        Assert.assertEquals("a", ah.getPartnerId());
        Assert.assertEquals("b", ah.getKeyId());
        Assert.assertNotNull(ah.getTimestamp());
        Assert.assertEquals("das_sig", ah.getSignature());

        ArgumentCaptor<CanonicalHttpMessage> signedMessageCaptor = ArgumentCaptor.forClass(CanonicalHttpMessage.class);
        Mockito.verify(this.mockHttpMessageSigner).sign(org.mockito.Matchers.any(AuthorizationHeader.class), signedMessageCaptor.capture());
        CanonicalHttpMessage httpResponse = signedMessageCaptor.getValue();
        Assert.assertNotNull(httpResponse);
        Assert.assertNull(httpResponse.getEntityDigest());
    }








    private static void provideHeaders(HttpServletRequest request, String headerName, final String ...values) {
        Mockito.when(request.getHeaders(headerName)).then(new Answer<Enumeration<String>>() {
            @Override
            public Enumeration<String> answer(InvocationOnMock invocation) {
                return Collections.enumeration(Arrays.asList(values));
            }
        });
        Mockito.when(request.getHeader(headerName)).thenReturn(values[0]);
        Mockito.when(request.getHeader(headerName)).thenReturn(values[0]);
    }

    private static HttpServletRequest getServletRequest() throws IOException {
        return getServletRequest("POST", "/fake/path", "foo=bar&hoge=hoge", "the entity");
    }

    private static HttpServletRequest getServletRequest(String method, String path, String qstr, String entity) throws IOException {
        HttpServletRequest ret = Mockito.mock(HttpServletRequest.class);
        Mockito.when(ret.getMethod()).thenReturn(method);
        Mockito.when(ret.getRequestURI()).thenReturn(path);
        Mockito.when(ret.getQueryString()).thenReturn(qstr);
        Mockito.when(ret.getHeaders(org.mockito.Matchers.anyString())).thenReturn(Collections.enumeration(Collections.emptyList()));

        final ByteArrayInputStream is;
        if (entity != null) {
            is = new ByteArrayInputStream(entity.getBytes(StandardCharsets.UTF_8));
        } else {
            is = new ByteArrayInputStream(new byte[0]);
        }
        Mockito.when(ret.getInputStream()).thenReturn(new ServletInputStream() {
            @Override
            public boolean isFinished() {
                throw new UnsupportedOperationException();
            }
            @Override
            public boolean isReady() {
                throw new UnsupportedOperationException();
            }
            @Override
            public void setReadListener(ReadListener readListener) {
                throw new UnsupportedOperationException();
            }

            @Override
            public int read() {
                return is.read();
            }
        });

        return ret;
    }

    private static HttpServletResponse getServletResponse() throws IOException {
        return getServletResponse(new ByteArrayOutputStream());
    }

    private static HttpServletResponse getServletResponse(final ByteArrayOutputStream outputStreamCapture) throws IOException {
        HttpServletResponse ret = Mockito.mock(HttpServletResponse.class);

        final LinkedHashMap<String, ArrayList<String>> headers = new LinkedHashMap<>();
        Mockito.doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocation) {
                String name = (String)invocation.getArguments()[0];
                String value = (String)invocation.getArguments()[1];
                if (!headers.containsKey(name)) {
                    headers.put(name, new ArrayList<>());
                }
                headers.get(name).add(value);
                return null;
            }
        }).when(ret).setHeader(org.mockito.Matchers.anyString(), org.mockito.Matchers.anyString());
        Mockito.when(ret.getHeaders(org.mockito.Matchers.anyString())).then(new Answer<Collection<String>>() {
            @Override
            public Collection<String> answer(InvocationOnMock invocation) {
                String name = (String)invocation.getArguments()[0];
                ArrayList<String> values = headers.get(name);
                return values == null ? Collections.emptyList() : values;
            }
        });

        Mockito.when(ret.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public boolean isReady() {
                throw new UnsupportedOperationException();
            }
            @Override
            public void setWriteListener(WriteListener writeListener) {
                throw new UnsupportedOperationException();
            }

            @Override
            public void write(int b) {
                outputStreamCapture.write(b);
            }
        });
        return ret;
    }

    private static String streamToString(InputStream is) throws IOException {
        return new String(IO.toByteArray(is), StandardCharsets.UTF_8);
    }
    private static String sha256Hex(String in) {
        return HexCodec.encodeString(
            DigestFactory.getSHA256().digest(in.getBytes(StandardCharsets.UTF_8))
        );
    }
}
