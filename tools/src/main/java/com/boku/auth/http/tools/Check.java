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
import com.boku.util.Joiner;

import java.io.IOException;
import java.util.List;
import java.util.Properties;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * See {@link #SYNOPSIS}
 */
public class Check {

    public static final String SYNOPSIS = "Verify a pre-signed HTTP request or response using a text file as input. (Can be used to check test vectors from spec.)";

    public static void main(String[] argv) throws IOException, InvalidAuthorizationHeaderException {
        // Parse command line arguments
        ArgvProcessor args = new ArgvProcessor(
            Check.class, SYNOPSIS, "<FILE|->", argv,
            "$0 test-vectors/test-5.1-standard-post.http",
            "cat test-vectors/test-5.1-standard-post.http | $0 -",
            "for file in test-vectors/*; do $0 -quiet $file && echo \"$file passed\"; done"
        );
        GeneralOptions generalOpts = new GeneralOptions();
        args.register(generalOpts);

        String filename = null;
        while (args.hasNext()) {
            if (filename == null) {
                filename = args.next();
            } else {
                args.usage("Unrecognized extra argument, '" + args.next() + "'");
            }
        }
        if (filename == null) {
            args.usage("Please supply a filename containing a HTTP message as the first argument");
        }

        // Load and parse the input file
        HTTPMessage httpMessage;
        try {
            httpMessage = HTTPMessage.parse(load(filename));
        } catch (HTTPMessage.ParseException ex) {
            die("Failed to parse input file " + filename + ": " + ex.getMessage());
            return;
        }

        // Dump out input HTTP request or response
        if (generalOpts.verbose) {
            println("Checking signature of the following:");
            println();
            println(indent(generalOpts.indent, httpMessage.toString()));
            println();
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

        // Get the Authorization header
        AuthorizationHeader ah;
        {
            final String authorizationHeaderName = httpMessage.isRequest() ? AuthorizationHeader.REQUEST_HEADER : AuthorizationHeader.RESPONSE_HEADER;
            HTTPMessage.Header hdr = httpMessage.findFirstHeader(authorizationHeaderName);
            if (hdr == null) {
                String type = httpMessage.isRequest() ? "request" : "response";
                die("Input HTTP " + type + " has no " + authorizationHeaderName + " header - nothing to check!");
                return;
            }
            ah = AuthorizationHeader.parse(hdr.value);
            List<String> errors = AuthorizationHeaderValidator.getErrors(ah);
            if (errors.size() > 0) {
                die("Invalid " + authorizationHeaderName + " header: " + Joiner.join(", ", errors));
            }
        }

        // Create the canonical form of the message for verification, and dump it out
        CanonicalHttpMessage canonicalHttpMessage = httpMessage.canonicalize(ah);
        if (generalOpts.verbose) {
            println("Generated ", canonicalHttpMessage.getClass().getSimpleName(), ":");
            println();
            println(indent(generalOpts.indent, canonicalHttpMessage.toString(new StringBuilder()).append(ah.getTimestamp()).toString()));
            println();
        }

        // Check the signature and exit accordingly
        String sig = httpMessageSigner.generateSignature(ah, canonicalHttpMessage);
        if (sig.equals(ah.getSignature())) {
            println("SIGNATURE OK");
            System.exit(0);
        } else {
            println("SIGNATURE MISMATCH - header says " + ah.getSignature() + ", we generated " + sig);
            System.exit(1);
        }
    }

}
