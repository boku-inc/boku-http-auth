package com.boku.auth.http.tools;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.auth.http.keyprovider.PropertiesKeyProvider;
import com.boku.auth.http.stringsigner.BasicStringSignerImpl;
import com.boku.auth.http.tools.shared.ArgvProcessor;
import com.boku.auth.http.tools.shared.Options;
import com.boku.auth.http.client.BokuAPIClient;
import com.boku.auth.http.client.exception.BokuAPIClientException;
import com.boku.auth.http.client.xml.XMLEntityMarshaller;
import com.boku.util.IO;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * See {@link #SYNOPSIS}
 */
public class Example_BokuAPIClient {

    public static final String SYNOPSIS = "Example showing how to send a POST using BokuAPIClient (from the boku-http-auth-client package).";

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.NONE)
    public static class ExampleRequest {
        @XmlAttribute
        public String type;
        @XmlElement
        public Long timestamp;
    }

    public static void main(String[] argv) throws IOException {
        // Parse command line arguments
        ArgvProcessor args = new ArgvProcessor(
            Example_BokuAPIClient.class, SYNOPSIS, "<URI>", argv,
            "$0 -partner-id my-merchant -key-id 1 https://us-api4-stage.boku.com/test/echo < post-body.xml",
            "$0 -partner-id my-merchant -key-id 1 https://us-api4-stage.boku.com/test/echo"
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
        String entityString = null;
        ExampleRequest exampleRequest = null;
        {
            byte[] entityData = readStdin();
            if (entityData != null) {
                entityString = new String(entityData, StandardCharsets.UTF_8);
            } else {
                err.println("No POST body supplied on stdin, will serialize a default instance of ExampleRequest...\n");
                exampleRequest = new ExampleRequest();
                exampleRequest.type = "test";
                exampleRequest.timestamp = System.currentTimeMillis();
            }
        }

        // Construct client once and reuse
        final BokuAPIClient client = getClient(opts.configFile);

        // Unsigned authorization header
        AuthorizationHeader authorizationHeader = new AuthorizationHeader();
        authorizationHeader.setPartnerId(opts.partnerId);
        authorizationHeader.setKeyId(opts.keyId);

        // Make request using client, the above header will be signed automatically

        try {
            // Use client supplied text as request body
            if (entityString != null) {
                String response = client.post(uri)
                    .withAuthorization(authorizationHeader)
                    .withHeader("Content-Type", opts.contentType) // Adds to authorizationHeader.signedHeaders
                    .withEntityString(entityString)
                    .execute();

                out.println("Response body:\n");
                out.println(response);
            }

            // Or use marshalling functionality
            else {
                String response = client.post(uri)
                    .withAuthorization(authorizationHeader)
                    .withEntity(exampleRequest)
                    .execute(); // NOTE: use .execute(ExampleResponse.class) to unmarshal the response also

                out.println("Response body:\n");
                out.println(response);
            }
        } catch (BokuAPIClientException ex) {
            error("Request failed: " + ex);
            ex.printStackTrace(err);
            if (ex.getResponse() != null) {
                warn("Printing full response:\n" + ex.getResponse());
            }
        }
    }

    /**
     * Create a reusable instance of BokuAPIClient
     */
    private static BokuAPIClient getClient(String configFile) throws FileNotFoundException {
        // Create the Apache HttpClient we will use
        // Note: you usually do not want the default HttpClient settings in production!
        HttpClient httpClient = HttpClientBuilder.create()
            .disableRedirectHandling() // Very important for security
            .build();

        // Use the given properties file to look up keys.
        // In production, you probably don't want to store keys in a properties file.
        PropertiesKeyProvider propertiesKeyProvider = PropertiesKeyProvider.fromFile(configFile);

        // The client needs a HttpMessageSigner (from core module) to sign the requests
        HttpMessageSigner httpMessageSigner = new HttpMessageSigner(
            new BasicStringSignerImpl(propertiesKeyProvider)
        );

        // Create our client instance
        return new BokuAPIClient(
            httpClient,
            httpMessageSigner,
            // This marshaller is used when passing objects to .withEntity(...). You can plug in others for e.g. JSON
            new XMLEntityMarshaller()
        );
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
