package com.boku.auth.http.tools;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.AuthorizationHeaderValidator;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.httpmessage.CanonicalHttpMessage;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.auth.http.keyprovider.PropertiesKeyProvider;
import com.boku.auth.http.stringsigner.BasicStringSignerImpl;
import com.boku.auth.http.tools.shared.ArgvProcessor;
import com.boku.auth.http.tools.shared.GeneralOptions;
import com.boku.auth.http.tools.shared.HTTPMessage;
import com.boku.auth.http.tools.shared.Options;
import com.boku.util.IO;
import com.boku.util.Joiner;
import com.boku.auth.http.server.AuthorizationContextProvider;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * Test server for debugging request signing and response signature checking.<br>
 * <br>
 * WARNING: This code is designed to help you test, it is NOT designed to be used on production. It exposes information
 * to the client that shouldn't be exposed, and the code itself is inefficient and overly verbose.<br>
 * <br>
 * For an example of how to implement authentication on the server side in Java, see {@link Example_ServletServer}
 * instead.
 */
public class Server {

    public static final String SYNOPSIS = "HTTP server that can verify request signatures and send signed responses. Serves local files and provides an /echo endpoint.";

    /**
     * Basic extension to content-type mapping for the file server. Add your own here if you need them for testing.
     */
    static final String[] TEXT_CONTENT_TYPES = {
        ".txt", "text/plain",
        ".xml", "text/xml",
        ".json", "application/json",
        ".md", "text/markdown",
    };

    static final class ServerOptions implements Options {

        int port = 8080;
        String root = ".";
        String defaultCharset = "UTF-8";

        @Override
        public void register(ArgvProcessor args) {
            args.addParam(
                "port", "<PORT>",
                value -> port = Integer.parseInt(value),
                "Listen on the given port number (Default: " + port + ", use 0 to allocate random port)"
            );
            args.addParam(
                "root", "<PATH>",
                value -> root = value,
                "Serve files starting from the given path (Default: " + root + ")"
            );
        }
    }

    public static void main(String[] argv) throws Exception {
        // Parse command line arguments
        ArgvProcessor args = new ArgvProcessor(
            Server.class, SYNOPSIS, null, argv,
            "$0 -port 12345 -root ~/files-to-serve"
        );
        ServerOptions serverOpts = new ServerOptions();
        args.register(serverOpts);
        GeneralOptions generalOpts = new GeneralOptions();
        args.register(generalOpts);
        while (args.hasNext()) {
            args.usage("Unrecognized extra argument, '" + args.next() + "'");
        }

        File root = new File(serverOpts.root).getCanonicalFile();
        if (!root.exists()) {
            die("Specified root " + serverOpts.root + " does not exist");
        }
        if (!root.isDirectory()) {
            die("Specified root " + serverOpts.root + " is not a directory");
        }

        // Load configuration file containing API keys
        Properties config = loadProperties(generalOpts.configFile);
        if (config == null) {
            die("Config file " + generalOpts.configFile + " does not exist");
            return;
        }
        PropertiesKeyProvider propsKeyProvider = new PropertiesKeyProvider(config);

        // Create a HttpMessageSigner
        HttpMessageSigner httpMessageSigner = new HttpMessageSigner(
            new BasicStringSignerImpl(propsKeyProvider)
        );

        org.eclipse.jetty.server.Server jetty = new org.eclipse.jetty.server.Server(serverOpts.port);
        ServletContextHandler servletHandler = new ServletContextHandler();
        jetty.setHandler(servletHandler);

        DebugServlet debugServlet = new DebugServlet(root, serverOpts.defaultCharset, generalOpts, httpMessageSigner);
        servletHandler.addServlet(new ServletHolder(debugServlet), "/");

        jetty.start();
        println();
        println("Listening on port ", serverOpts.port, " and serving files from ", root);
        println();
        println("Note: All paths, including static files, support GET / POST / PUT / DELETE.");
        println();
        println("There is an /echo endpoint which will send back at you any data sent via POST / PUT, including headers.");
        println("This allows for easy response testing without setting up files in advance.");
        println();
    }

    private static class DebugServlet extends HttpServlet {
        final File root;
        final String defaultCharset;
        final GeneralOptions generalOpts;
        final HttpMessageSigner httpMessageSigner;

        DebugServlet(File root, String defaultCharset, GeneralOptions generalOpts, HttpMessageSigner httpMessageSigner) {
            this.root = root;
            this.defaultCharset = defaultCharset;
            this.generalOpts = generalOpts;
            this.httpMessageSigner = httpMessageSigner;
        }

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            // Read in the request so we can print it.
            HTTPMessage httpReq = toHTTPMessage(req);
            if (generalOpts.verbose) {
                println("Received the following HTTP request:");
                println();
                println(indent(generalOpts.indent, httpReq.toString()));
                println();
            } else {
                println(" => ", req.getMethod(), " ", req.getRequestURI());
            }

            // Get Authorization header
            AuthorizationHeader ah;
            {
                final String headerName = AuthorizationHeader.REQUEST_HEADER;
                String ahString = req.getHeader(headerName);
                if (ahString == null) {
                    returnError(resp, HttpStatus.UNAUTHORIZED_401,
                        "no " + headerName + " header supplied");
                    return;
                }
                try {
                    ah = AuthorizationHeader.parse(ahString);
                } catch (IllegalArgumentException ex) {
                    returnError(resp, HttpStatus.UNAUTHORIZED_401, "invalid " + headerName + " header: " + ex.getMessage());
                    return;
                }
                List<String> errors = AuthorizationHeaderValidator.getErrors(ah);
                if (!errors.isEmpty()) {
                    returnError(resp, HttpStatus.UNAUTHORIZED_401, "invalid " + headerName + " header: " + Joiner.join(", " , errors));
                    return;
                }
            }

            // Create the canonical form of the request for verification, and dump it out
            CanonicalHttpMessage canonicalRequest = httpReq.canonicalize(ah);
            if (generalOpts.verbose) {
                println("Generated ", canonicalRequest.getClass().getSimpleName(), ":");
                println();
                println(indent(generalOpts.indent, canonicalRequest.toString(new StringBuilder()).append(ah.getTimestamp()).toString()));
                println();
            }

            // Check the signature
            String sig;
            try {
                sig = httpMessageSigner.generateSignature(ah, canonicalRequest);
            } catch (InvalidAuthorizationHeaderException ex) {
                returnError(resp, HttpStatus.UNAUTHORIZED_401, ex.getMessage());
                return;
            }
            if (sig.equals(ah.getSignature())) {
                println("SIGNATURE OK");
            } else {
                String message = "SIGNATURE MISMATCH - header says " + ah.getSignature() + ", we generated " + sig;
                println(message);
                returnError(resp, HttpStatus.UNAUTHORIZED_401, message);
                return;
            }

            // Check the age of the request.
            // Usually this should be done before checking the sig, but doing it this way round here allows for easier testing
            {
                long now = System.currentTimeMillis() / 1000;
                if (Math.abs(now - ah.getTimestamp()) > AuthorizationContextProvider.TIMESTAMP_VALIDITY_PERIOD_SECONDS) {
                    println("Authorization header timestamp outside of validity window - age ", now - ah.getTimestamp(), "s");
                    returnError(resp, HttpStatus.UNAUTHORIZED_401, "Timestamp outside of validity window");
                    return;
                }
            }

            Set<String> signedHeaders = ah.getSignedHeaders().stream().map(String::toLowerCase).collect(Collectors.toSet());
            for (HTTPMessage.Header hdr : httpReq.headers) {
                for (String name : RECOMMENDED_SIGNED_REQUEST_HEADERS) {
                    boolean shouldBeSigned = name.charAt(name.length() - 1) == '-'
                        ? hdr.name.toLowerCase().startsWith(name)
                        : hdr.name.toLowerCase().equals(name);
                    if (shouldBeSigned && !signedHeaders.contains(name)) {
                        warn("Client did not sign request header - `" + hdr.name + ": " + hdr.value + "`");
                    }
                }
            }

            // From this point onwards we will sign whatever response we send
            // Get the response entity from either a file, or the special /echo endpoint
            byte[] responseEntity;
            RESP: {
                if ("/echo".equals(req.getRequestURI())) {
                    resp.setStatus(200);
                    resp.setContentType(req.getContentType());
                    responseEntity = httpReq.entity;
                }
                else {
                    // Load requested file
                    File file = new File(this.root, req.getRequestURI());
                    FileInputStream fis;
                    try {
                        fis = new FileInputStream(file);
                    } catch (FileNotFoundException fnfe) {
                        responseEntity = prepareError(resp, HttpStatus.NOT_FOUND_404, "file does not exist - " + file.getAbsolutePath());
                        break RESP;
                    }
                    responseEntity = IO.toByteArray(fis);

                    resp.setStatus(200);
                    resp.setContentType(inferContentType(req.getRequestURI()));
                }
            }

            // Set content-length, and if HEAD remove the actual entity itself from the response
            if (responseEntity != null) {
                resp.setContentLength(responseEntity.length);
            }
            if ("HEAD".equals(req.getMethod())) {
                responseEntity = null;
            }

            HTTPMessage httpResp = toHTTPMessage(resp, responseEntity);

            // Create the response Authorization header
            AuthorizationHeader respAh = new AuthorizationHeader();
            respAh.setScheme(HttpMessageSigner.SCHEME);
            respAh.setPartnerId(ah.getPartnerId());
            respAh.setKeyId(ah.getKeyId());
            if (resp.getContentType() != null) {
                respAh.getSignedHeaders().add("Content-Type");
            }

            // Get canonical response and sign it
            CanonicalHttpMessage canonicalResponse = httpResp.canonicalize(respAh);
            httpMessageSigner.sign(respAh, canonicalResponse);
            if (generalOpts.verbose) {
                println("Signed this ", canonicalResponse.getClass().getSimpleName(), ":");
                println();
                println(indent(generalOpts.indent, canonicalResponse.toString(new StringBuilder()).append(respAh.getTimestamp()).toString()));
                println();
            }

            // Set the signed response header
            resp.setHeader(AuthorizationHeader.RESPONSE_HEADER, respAh.toString());

            if (generalOpts.verbose) {
                println("Final response to send:");
                println();
                println(indent(generalOpts.indent, toHTTPMessage(resp, httpResp.entity).toString()));
                println();
            } else {
                println(" <= ", httpResp.startLine);
                println();
            }

            if (httpResp.entity != null) {
                resp.getOutputStream().write(httpResp.entity);
            }
        }

        String inferContentType(String uri) {
            for (int i = 0; i < TEXT_CONTENT_TYPES.length; i += 2) {
                if (uri.toLowerCase().endsWith(TEXT_CONTENT_TYPES[i])) {
                    return TEXT_CONTENT_TYPES[i + 1] + "; charset=" + this.defaultCharset;
                }
            }
            return "application/octet-stream";
        }

        static void returnError(HttpServletResponse resp, int sc, String reason) throws IOException {
            resp.getOutputStream().write(prepareError(resp, sc, reason));
        }

        static byte[] prepareError(HttpServletResponse resp, int sc, String reason) {
            String status = HttpStatus.getMessage(sc);
            String message = sc + " " + status + ": " + reason;
            error("Returning HTTP " + message);
            resp.setStatus(sc);
            resp.setContentType("text/plain; charset=utf8");
            return message.getBytes(StandardCharsets.UTF_8);
        }

        /**
         * Convert a servlet HttpServletRequest to {@link HTTPMessage} for easy printing and conversion to canonical request.
         */
        static HTTPMessage toHTTPMessage(HttpServletRequest httpRequest) throws IOException {
            HTTPMessage http = new HTTPMessage();
            {
                StringBuilder line = new StringBuilder()
                    .append(httpRequest.getMethod())
                    .append(' ')
                    .append(httpRequest.getRequestURI());
                if (httpRequest.getQueryString() != null) {
                    line.append('?').append(httpRequest.getQueryString());
                }
                line.append(' ').append("HTTP/1.1"); // Not accessible from servlet API, but not really necessary anyway
                http.startLine = line.toString();
            }

            Enumeration<String> headerNames = httpRequest.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                Enumeration<String> values = httpRequest.getHeaders(headerName);
                while (values.hasMoreElements()) {
                    http.headers.add(new HTTPMessage.Header(headerName, values.nextElement()));
                }
            }
            http.entity = IO.toByteArray(httpRequest.getInputStream());
            if (http.entity != null && http.entity.length == 0) {
                http.entity = null;
            }
            if (http.entity != null) {
                HTTPMessage.determineCharset(http);
            }
            return http;
        }

        /**
         * Convert a servlet HttpServletResponse to {@link HTTPMessage} for easy printing and conversion to canonical request.
         */
        static HTTPMessage toHTTPMessage(HttpServletResponse httpResponse, byte[] entity) {
            HTTPMessage http = new HTTPMessage();
            int sc = httpResponse.getStatus();

            http.startLine = "HTTP/1.1 " + sc + ' ' + HttpStatus.getMessage(sc);
            for (String headerName : httpResponse.getHeaderNames()) {
                for (String value : httpResponse.getHeaders(headerName)) {
                    http.headers.add(new HTTPMessage.Header(headerName, value));
                }
            }
            http.entity = entity;
            if (http.entity != null) {
                HTTPMessage.determineCharset(http);
            }
            return http;
        }

        static final String[] RECOMMENDED_SIGNED_REQUEST_HEADERS = {
            "accept",
            "accept-charset",
            "content-type",
            "if-",
            "range"
        };
    }
}
