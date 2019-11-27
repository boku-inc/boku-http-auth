package com.boku.auth.http.tools;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.AuthorizationException;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.httpmessage.CanonicalHttpResponse;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.auth.http.keyprovider.PropertiesKeyProvider;
import com.boku.auth.http.stringsigner.BasicStringSignerImpl;
import com.boku.auth.http.tools.shared.ArgvProcessor;
import com.boku.auth.http.tools.shared.Options;
import com.boku.auth.http.httpclient.ApacheHttpClientCanonicalHttpMessageFactory;
import com.boku.util.IO;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * See {@link #SYNOPSIS}
 */
public class Example_ApacheHttpClient {

    public static final String SYNOPSIS = "Example showing how integrate auth on top of plain Apache HttpClient usage (no Boku client) to send a POST request";

    public static void main(String[] argv) throws IOException {
        // Parse command line arguments
        ArgvProcessor args = new ArgvProcessor(
            Example_ApacheHttpClient.class, SYNOPSIS, "<URI>", argv,
            "$0 -partner-id my-merchant -key-id 1 https://us-api4-stage.boku.com/billing/3.0/example < post-body.xml"
        );
        Opts opts = new Opts();
        args.register(opts);
        String uri = null;
        while (args.hasNext()) {
            if (uri == null) {
                uri = args.next();
            } else {
                args.usage("Unrecognized extra argument, '" + args.next() + "'");
            }
        }
        if (uri == null) {
            args.usage("No request URI supplied");
        }

        // Read the POST body from stdin
        byte[] entityData;
        {
            entityData = readStdin();
            if (entityData == null) {
                args.usage("No POST body data supplied on stdin");
                return;
            }
        }


        //
        // --- Begin component setup code ---
        //

        // Create the Apache HttpClient we will use
        // Note: you usually do not want the default HttpClient settings in production!
        HttpClient httpClient = HttpClientBuilder.create()
            .disableRedirectHandling() // Very important for security
            .setDefaultRequestConfig(RequestConfig.copy(RequestConfig.DEFAULT)
                .setConnectTimeout(10_000)
                .setSocketTimeout(60_000)
                .setConnectionRequestTimeout(1_000)
                .build()
            )
            .build();

        // Use the given properties file to look up keys.
        // In production, you probably don't want to store keys in a properties file.
        PropertiesKeyProvider propertiesKeyProvider = PropertiesKeyProvider.fromFile(opts.configFile);

        // The client needs a HttpMessageSigner (from core module) to sign the requests
        HttpMessageSigner httpMessageSigner = new HttpMessageSigner(
            new BasicStringSignerImpl(propertiesKeyProvider)
        );

        // Converts Apache HttpRequests and HttpResponses into the canonical message format used by HttpMessageSigner
        ApacheHttpClientCanonicalHttpMessageFactory canonicalHttpMessageFactory = new ApacheHttpClientCanonicalHttpMessageFactory();


        //
        // --- End of component setup, begin of per-request code ---
        //

        // Create Apache HttpClient request
        HttpPost post = new HttpPost(uri);
        post.addHeader("Content-Type", opts.contentType);
        post.setEntity(new ByteArrayEntity(entityData));

        // Unsigned authorization header
        AuthorizationHeader authorizationHeader = new AuthorizationHeader();
        authorizationHeader.setPartnerId(opts.partnerId);
        authorizationHeader.setKeyId(opts.keyId);
        authorizationHeader.getSignedHeaders().add("Content-Type");

        // Create the canonical HTTP request representation from above
        CanonicalHttpRequest canonicalRequest = canonicalHttpMessageFactory.createRequest(
            authorizationHeader.getSignedHeaders(),
            post
        );

        // Sign it, modifying the AuthorizationHeader in-place.
        httpMessageSigner.sign(authorizationHeader, canonicalRequest);

        // Set resultant header on the HttpClient request
        post.setHeader(AuthorizationHeader.REQUEST_HEADER, authorizationHeader.toString());

        // Execute HTTP request and get response entity
        HttpResponse httpResponse = httpClient.execute(post);
        ContentType respEntityContentType = null;
        byte[] respEntityData = null;
        try {
            HttpEntity httpEntity = httpResponse.getEntity();
            if (httpEntity != null) {
                respEntityContentType = ContentType.get(httpEntity);
                if (respEntityContentType == null) {
                    respEntityContentType = ContentType.APPLICATION_OCTET_STREAM;
                }
                respEntityData = EntityUtils.toByteArray(httpEntity);
            }
        } finally {
            EntityUtils.consumeQuietly(httpResponse.getEntity());
        }

        // Verify the response signature before we do any processing
        Header[] respAuthHeaders = httpResponse.getHeaders(AuthorizationHeader.RESPONSE_HEADER);
        if (respAuthHeaders.length != 1) {
            throw new IllegalStateException(
                "Got " + httpResponse.getStatusLine() + " with " + respAuthHeaders.length + " "
                    + AuthorizationHeader.RESPONSE_HEADER + " headers, expected 1: " + Arrays.toString(respAuthHeaders)
            );
        }
        String respAuthHeaderValue = respAuthHeaders[0].getValue();
        AuthorizationHeader respAuthHeader;
        try {
            respAuthHeader = AuthorizationHeader.parse(respAuthHeaderValue);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException(
                "Invalid " + AuthorizationHeader.RESPONSE_HEADER + " header: " + ex.getMessage()
                + " (header value: " + respAuthHeaderValue + ", " + httpResponse.getStatusLine() + ")"
            );
        }
        CanonicalHttpResponse canonicalResponse = canonicalHttpMessageFactory.createResponse(
            respAuthHeader.getSignedHeaders(),
            httpResponse,
            respEntityData
        );
        try {
            httpMessageSigner.verifySignature(respAuthHeader, canonicalResponse);
        } catch (AuthorizationException ex) {
            throw new IllegalStateException("Failed to verify signature of " + httpResponse.getStatusLine()
                + " response: " + ex.getMessage(), ex);
        }

        // Signature is good, response can be trusted.
        // Note: you probably want to check status code here
        System.out.println(httpResponse.getStatusLine());

        // Print out the response body
        if (respEntityData == null) {
            System.out.println("No response body.");
        } else {
            System.out.println("Response Content-Type: " + respEntityContentType);
            System.out.println();

            // Convert to a string for display
            Charset charset = respEntityContentType.getCharset();
            if (charset == null) {
                System.out.println("Response Content-Type header does not specify charset, interpreting response as ASCII!");
                charset = StandardCharsets.US_ASCII;
            }
            String respEntityString = new String(respEntityData, charset);
            System.out.println(respEntityString);
        }

    }

    private static byte[] readStdin() throws IOException {
        if (System.in.available() == 0) {
            return null;
        }
        return IO.toByteArray(System.in);
    }

    private static class Opts implements Options {

        String configFile = "config.properties";
        String partnerId;
        String keyId;
        String contentType = "text/xml; charset=UTF-8";

        @Override
        public void register(ArgvProcessor args) {
            args.addParam(
                "config", "<FILE>",
                value -> configFile = value,
                "Use specified config file (Default: " + configFile + ")"
            );
            args.addParam(
                "partner-id", "<VALUE>",
                value -> partnerId = value,
                "Sign using the given partner-id's key (must exist in config)"
            );
            args.addParam(
                "key-id", "<VALUE>",
                value -> keyId = value,
                "Sign using the key by the given ID (must exist in config)"
            );
            args.addParam(
                "content-type", "<VALUE>",
                value -> contentType = value,
                "Use specified value in the Content-Type header (Default: " + contentType + ")"
            );
        }

        @Override
        public void finish(ArgvProcessor args) {
            if (partnerId == null) {
                args.usage("No -partner-id specified");
            }
            if (keyId == null) {
                args.usage("No -key-id specified");
            }
        }
    }

}
