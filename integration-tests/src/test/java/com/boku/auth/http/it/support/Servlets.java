package com.boku.auth.http.it.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.AuthorizationException;
import com.boku.util.IO;
import com.boku.auth.http.server.AuthorizationContextProvider;

@SuppressWarnings("serial")
public class Servlets {

    public static HttpServlet withAuth(final AuthorizationContextProvider authContextProvider, final HttpRequestHandler requestHandler) {
        return new HttpServlet() {
            @Override
            protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                // Note: the auth provider assumes you will consume the stream before checking the auth.
                // This was an optimization made to save on request buffering, but my be a broken assumption in many
                // cases.
                byte[] requestEntity = IO.toByteArray(req.getInputStream());

                try {
                    authContextProvider.get();
                } catch (AuthorizationException ex) {
                    resp.setStatus(401);
                    resp.setHeader("Content-Type", "text/plain");
                    resp.getOutputStream().print(ex.getMessage());
                    return;
                }
                requestHandler.handle(req, resp, requestEntity);
            }
        };
    }

    public static HttpServlet noAuth(final HttpRequestHandler requestHandler) {
        return new HttpServlet() {
            @Override
            protected void service(HttpServletRequest req, HttpServletResponse resp) {
                try {
                    requestHandler.handle(req, resp, IO.toByteArray(req.getInputStream()));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    public static class PingHandler implements HttpRequestHandler {
        @Override
        public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
            resp.setHeader("Content-Type", "text/plain; charset=UTF-8");
            if (req.getContentLength() > 0) {
                String requestText = new String(requestEntity, req.getCharacterEncoding());
                resp.getOutputStream().write((req.getMethod() + " '" + requestText + "': pong").getBytes(StandardCharsets.UTF_8));
            } else {
                resp.getOutputStream().print(req.getMethod() + ": pong");
            }
        }
    }

    public static class EchoHandler implements HttpRequestHandler {
        @Override
        public void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException {
            resp.setHeader("Content-Type", "text/plain; charset=UTF-8");
            resp.setCharacterEncoding("UTF-8");
            String uri = req.getRequestURI();
            if (req.getQueryString() != null) {
                uri += "?" + req.getQueryString();
            }
            resp.getOutputStream().print(req.getMethod() + " " + uri + "\n");

            {
                List<String> echoedHeaders = new ArrayList<>();
                Enumeration<String> headerNames = req.getHeaderNames();
                while (headerNames.hasMoreElements()) {
                    String hdr = headerNames.nextElement();
                    if (AuthorizationHeader.REQUEST_HEADER.equals(hdr) || hdr.startsWith("X-BOKU-") || hdr.equals("Content-Type")) {
                        Enumeration<String> values = req.getHeaders(hdr);
                        while (values.hasMoreElements()) {
                            echoedHeaders.add(hdr + ": " + values.nextElement());
                        }
                    }
                }
                Collections.sort(echoedHeaders);
                for (String hdrPair : echoedHeaders) {
                    resp.getOutputStream().print(hdrPair + "\n");
                }
            }

            if (req.getContentLength() > 0) {
                String requestText = new String(requestEntity, req.getCharacterEncoding());
                resp.getOutputStream().write(("\n" + requestText).getBytes(StandardCharsets.UTF_8));
            }
        }
    }

}
