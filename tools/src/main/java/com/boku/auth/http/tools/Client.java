package com.boku.auth.http.tools;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.InvalidAuthorizationHeaderException;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.httpmessage.CanonicalHttpResponse;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.auth.http.keyprovider.PropertiesKeyProvider;
import com.boku.auth.http.stringsigner.BasicStringSignerImpl;
import com.boku.auth.http.tools.shared.ArgvProcessor;
import com.boku.auth.http.tools.shared.AuthHeaderOptions;
import com.boku.auth.http.tools.shared.GeneralOptions;
import com.boku.auth.http.tools.shared.HTTPMessage;
import com.boku.auth.http.tools.shared.Options;
import com.boku.auth.http.httpclient.ApacheHttpClientCanonicalHttpMessageFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.RequestLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * Test client that can be used for verifying your server implementation against a known working client implementation,
 * and for calling staging or production to verify that you have the correct keys.<br>
 * <br>
 * This client should be able to send any arbitrary HTTP request, similar to how you might use curl or wget for testing,
 * just with added request signing capability.
 */
public class Client {

    public static final String SYNOPSIS = "Sign and send arbitrary HTTP requests, and verify response signatures";

    private static final class HTTPClientOptions implements Options {
        String requestBodyFilename = null;
        ArrayList<Header> headers = new ArrayList<>();
        ArrayList<String> signedHeaders = new ArrayList<>();
        boolean binaryOutput = false;

        @Override
        public void register(ArgvProcessor args) {
            args.addParam(
                "body", "<FILE|->",
                value -> requestBodyFilename = value,
                "Load the request body from the given file. Specify '-' to load from stdin."
            );
            args.addParam(
                "h", "<HEADER>",
                value -> headers.add(parseHeader(value)),
                "Send the given HTTP header, but don't sign. Specify multiple times for multiple headers."
            );
            args.addParam(
                "H", "<HEADER>",
                value -> {
                    Header hdr = parseHeader(value);
                    headers.add(hdr);
                    signedHeaders.add(hdr.getName());
                },
                "Sign and send the given HTTP header. Specify multiple times for multiple headers. Equivalent to `-h 'N: V' -sign-header N`."
            );
            args.addFlag(
                "bin",
                () -> binaryOutput = true,
                "Output response body raw, rather than trying to decode text based on charset. (Only applies in -quiet mode.)"
            );
        }

        private static Header parseHeader(String value) {
            Matcher m = Pattern.compile("^(\\S+):\\s*(.*)").matcher(value);
            if (!m.matches()) {
                die("Invalid HTTP header, '" + value + "'");
            }
            return new BasicHeader(m.group(1), m.group(2));
        }

        public HttpClient createClient() {
            return HttpClientBuilder
                .create()
                .setDefaultRequestConfig(RequestConfig.copy(RequestConfig.DEFAULT)
                    .setConnectTimeout(5_000)
                    .setSocketTimeout(30_000)
                    .setConnectionRequestTimeout(5_000)
                    .build()
                )
                .build();
        }
    }

    public static void main(String[] argv) throws IOException, InvalidAuthorizationHeaderException {
        // Parse command line arguments
        ArgvProcessor args = new ArgvProcessor(
            Client.class, SYNOPSIS, "<METHOD> <URI>", argv,
            "$0 -H \"Content-Type: text/xml; charset=utf8\" -body example-request.xml POST https://us-api4-stage.boku.com/billing/3.0/charge",
            "echo \"example notification body\" | $0 -H \"Content-Type: text/plain; charset=utf8\" -body - POST http://localhost:12345/my-server-implementation",
            "$0 -quiet GET http://localhost:8080/example.txt > file-contents.txt"
        );
        GeneralOptions generalOpts = new GeneralOptions();
        args.register(generalOpts);
        AuthHeaderOptions authHeaderOpts = new AuthHeaderOptions();
        args.register(authHeaderOpts);
        HTTPClientOptions httpOpts = new HTTPClientOptions();
        args.register(httpOpts);

        String method = null;
        String uri = null;
        while (args.hasNext()) {
            if (method == null) {
                method = args.next();
            } else if (uri == null) {
                uri = args.next();
            } else {
                args.usage("Unrecognized extra argument, '" + args.next() + "'");
            }
        }
        if (method == null) {
            args.usage("No HTTP request method supplied");
        }
        if (uri == null) {
            args.usage("No HTTP request URI supplied");
        }

        // Combine the header names referenced by the -sign-header and -H options
        for (String headerName : httpOpts.signedHeaders) {
            if (!containsIgnoreCase(authHeaderOpts.ah.getSignedHeaders(), headerName)) {
                authHeaderOpts.ah.getSignedHeaders().add(headerName);
            }
        }

        // Load the request body, if any
        byte[] requestEntity = null;
        if (httpOpts.requestBodyFilename != null) {
            requestEntity = load(httpOpts.requestBodyFilename);
            if (generalOpts.verbose) {
                println("Read " + requestEntity.length + " bytes of request body data from " + httpOpts.requestBodyFilename);
            }
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

        // Construct HttpClient request
        HttpUriRequest httpRequest = createHttpClientRequest(method, uri);
        if (requestEntity != null) {
            if (httpRequest instanceof HttpEntityEnclosingRequest) {
                ((HttpEntityEnclosingRequest)httpRequest).setEntity(new ByteArrayEntity(requestEntity));
            } else {
                throw new IllegalStateException("Cannot supply HTTP request entity for method " + method + " req " + httpRequest.getClass());
            }
        }
        for (Header header : httpOpts.headers) {
            httpRequest.addHeader(header);
        }

        // Set up the Authorization header...
        AuthorizationHeader ah = authHeaderOpts.ah;

        // Pick a default partner-id and key-id if not specified
        if (ah.getPartnerId() == null && ah.getKeyId() == null) {
            String[] defaultPartner = propsKeyProvider.getDefaultPartnerKeyId();
            ah.setPartnerId(defaultPartner[0]);
            ah.setKeyId(defaultPartner[1]);
        }

        ApacheHttpClientCanonicalHttpMessageFactory canonicalHttpMessageFactory = new ApacheHttpClientCanonicalHttpMessageFactory();

        // Sign request
        CanonicalHttpRequest canonicalRequest = canonicalHttpMessageFactory.createRequest(
            ah.getSignedHeaders(),
            httpRequest
        );

        // Sign the header and print canonical message
        httpMessageSigner.sign(ah, canonicalRequest);
        if (generalOpts.verbose) {
            println("Signed this ", canonicalRequest.getClass().getSimpleName(), ":");
            println();
            println(indent(generalOpts.indent, canonicalRequest.toString(new StringBuilder()).append(ah.getTimestamp()).toString()));
            println();
        }

        // Set the completed Authorization header on the HTTP request for sending
        httpRequest.setHeader(AuthorizationHeader.REQUEST_HEADER, ah.toString());

        if (generalOpts.verbose) {
            println("Final request to send:");
            println();
            println(indent(generalOpts.indent, toHTTPMessage(httpRequest).toString()));
            println();
        }

        HttpClient httpClient = httpOpts.createClient();

        // Send
        HttpResponse httpResponse;
        try {
            httpResponse = httpClient.execute(httpRequest);
        } catch (IOException ex) {
            die("Failed to send HTTP request: " + ex);
            return;
        }

        // Process response
        if (generalOpts.verbose) {
            println("Server responded ", httpResponse.getStatusLine());
        }
        HTTPMessage response;
        {
            byte[] responseEntityData = null;
            HttpEntity responseEntity = httpResponse.getEntity();
            if (responseEntity != null) {
                try {
                    responseEntityData = EntityUtils.toByteArray(responseEntity);
                } catch (IOException ex) {
                    die("Failed to read " + httpResponse.getStatusLine() + " response body: " + ex);
                    return;
                }
            }
            response = toHTTPMessage(httpResponse, responseEntityData);
        }
        if (generalOpts.verbose) {
            println("Full HTTP response:");
            println();
            println(indent(generalOpts.indent, response.toString()));
            println();
        }

        // Get and parse response signature header
        AuthorizationHeader respAuthHeader;
        {
            Header[] respAuthHeaders = httpResponse.getHeaders(AuthorizationHeader.RESPONSE_HEADER);
            if (respAuthHeaders.length != 1) {
                die("Server " + httpResponse.getStatusLine() + " response had " + respAuthHeaders.length + " " + AuthorizationHeader.RESPONSE_HEADER + " headers!");
                return;
            }
            String respAuthHeaderValue = respAuthHeaders[0].getValue();
            try {
                respAuthHeader = AuthorizationHeader.parse(respAuthHeaderValue);
            } catch (IllegalArgumentException ex) {
                die("Server returned invalid " + AuthorizationHeader.RESPONSE_HEADER + " header: " + ex.getMessage()
                    + " (header value: " + respAuthHeaderValue + ")"
                );
                return;
            }
        }

        // Create the canonical form of the response for verification, and dump it out
        CanonicalHttpResponse canonicalResponse = canonicalHttpMessageFactory.createResponse(
            respAuthHeader.getSignedHeaders(),
            httpResponse,
            response.entity
        );
        if (generalOpts.verbose) {
            println("Will verify this response message-to-sign:");
            println();
            println(indent(generalOpts.indent, canonicalResponse.toString(new StringBuilder()).append(respAuthHeader.getTimestamp()).toString()));
            println();
        }

        // Calculate what we think is the correct signature, and compare against what we got
        String responseSignature = respAuthHeader.getSignature();
        String correctSignature = httpMessageSigner.generateSignature(respAuthHeader, canonicalResponse);
        if (correctSignature.equals(responseSignature)) {
            if (generalOpts.verbose) {
                println("Response signature OK!");
            }
        } else {
            die("Response signature mismatch: expected " + correctSignature + ", got " + responseSignature);
        }

        // In non-verbose mode, output response body and status
        if (httpResponse.getStatusLine().getStatusCode() / 100 != 2) {
            warn("Response status: " + httpResponse.getStatusLine().toString());
        }
        if (response.entity != null) {
            if (httpOpts.binaryOutput) {
                out.write(response.entity);
            } else {
                out.print(response.entityString());
            }
        }
    }

    /**
     * Given a HTTP method name and URI, return an instance of the appropriate {@link HttpUriRequest} sub-class.
     */
    private static HttpUriRequest createHttpClientRequest(String method, String uri) {
        StringBuilder methodName = new StringBuilder(method);
        methodName.setCharAt(0, Character.toUpperCase(methodName.charAt(0)));
        for (int i = 1; i < methodName.length(); i++) {
            methodName.setCharAt(i, Character.toLowerCase(methodName.charAt(i)));
        }
        String className = "org.apache.http.client.methods.Http" + methodName;
        Class<? extends HttpUriRequest> cls;
        try {
            //noinspection unchecked
            cls = (Class<? extends HttpUriRequest>)Class.forName(className);
        } catch (ClassNotFoundException ex) {
            die("Unsupported HTTP method, '" + method + "'");
            throw new IllegalStateException();
        }
        Constructor<? extends HttpUriRequest> ctor;
        try {
            ctor = cls.getConstructor(String.class);
        } catch (NoSuchMethodException ex) {
            throw new IllegalStateException(cls.getCanonicalName() + " does not have a constructor taking a String URI");
        }
        try {
            return ctor.newInstance(uri);
        } catch (InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException("Error invoking __ctor(String) on " + cls, ex);
        } catch (InvocationTargetException ex) {
            if (ex.getCause() instanceof RuntimeException) {
                throw (RuntimeException)ex.getCause();
            }
            throw new IllegalStateException(ex.getCause());
        }
    }

    /**
     * Convert an Apache HttpUriRequest to {@link HTTPMessage} for easier debug printing etc.
     */
    private static HTTPMessage toHTTPMessage(HttpUriRequest httpRequest) {
        HTTPMessage http = new HTTPMessage();
        {
            RequestLine rl = httpRequest.getRequestLine();
            URI uri = httpRequest.getURI();
            StringBuilder line = new StringBuilder()
                .append(rl.getMethod())
                .append(' ')
                .append(uri.getRawPath());
            if (uri.getRawQuery() != null) {
                line.append('?').append(uri.getRawQuery());
            }
            line.append(' ').append(rl.getProtocolVersion());
            http.startLine = line.toString();
            if (uri.getHost() != null) {
                http.headers.add(new HTTPMessage.Header("Host", uri.getHost()));
            }
        }

        for (Header header : httpRequest.getAllHeaders()) {
            http.headers.add(new HTTPMessage.Header(header.getName(), header.getValue()));
        }
        if (httpRequest instanceof HttpEntityEnclosingRequest) {
            HttpEntity entity = ((HttpEntityEnclosingRequest)httpRequest).getEntity();
            if (entity != null) {
                try {
                    http.entity = EntityUtils.toByteArray(entity);
                } catch (IOException e) {
                    throw new IllegalStateException("Error getting entity content");
                }
            }
        }
        HTTPMessage.determineCharset(http);
        return http;
    }

    /**
     * Convert an Apache HttpResponse to {@link HTTPMessage} so we can use some of its util methods.
     */
    private static HTTPMessage toHTTPMessage(HttpResponse httpRequest, byte[] entity) {
        HTTPMessage http = new HTTPMessage();
        http.startLine = httpRequest.getStatusLine().toString();
        for (Header header : httpRequest.getAllHeaders()) {
            http.headers.add(new HTTPMessage.Header(header.getName(), header.getValue()));
        }
        http.entity = entity;
        HTTPMessage.determineCharset(http);
        return http;
    }

    private static boolean containsIgnoreCase(Iterable<String> haystack, String needle) {
        for (String e : haystack) {
            if (needle.equalsIgnoreCase(e)) {
                return true;
            }
        }
        return false;
    }
}
