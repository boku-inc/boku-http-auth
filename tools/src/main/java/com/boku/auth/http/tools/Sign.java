package com.boku.auth.http.tools;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.httpmessage.CanonicalHttpMessage;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.auth.http.keyprovider.PropertiesKeyProvider;
import com.boku.auth.http.stringsigner.BasicStringSignerImpl;
import com.boku.auth.http.tools.shared.ArgvProcessor;
import com.boku.auth.http.tools.shared.GeneralOptions;
import com.boku.auth.http.tools.shared.AuthHeaderOptions;
import com.boku.auth.http.tools.shared.HTTPMessage;

import java.io.IOException;
import java.util.Properties;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * See {@link #SYNOPSIS}
 */
public class Sign {

    public static final String SYNOPSIS = "Sign a HTTP request or response using a text file as input";

    public static void main(String[] argv) throws IOException {
        // Parse command line arguments
        ArgvProcessor args = new ArgvProcessor(
            Sign.class, SYNOPSIS, "<FILE|->", argv,
            "$0 test-vectors/test-5.1-standard-post.http",
            "echo -en \"POST /example HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Type: text/plain;charset=utf8\\r\\n\\r\\nExample request body\\n\" | $0 -sign-header Content-Type -"
        );
        GeneralOptions generalOpts = new GeneralOptions();
        args.register(generalOpts);
        AuthHeaderOptions authHeaderOpts = new AuthHeaderOptions();
        args.register(authHeaderOpts);

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

        // Header name differs for request vs response
        String authorizationHeaderName = httpMessage.isRequest() ? AuthorizationHeader.REQUEST_HEADER : AuthorizationHeader.RESPONSE_HEADER;

        // Warn if there is an existing Authorization header
        {
            HTTPMessage.Header hdr = httpMessage.findFirstHeader(authorizationHeaderName);
            if (hdr != null) {
                warn("Found existing " + authorizationHeaderName + " header - did you mean to use `check`? Ignoring: " + hdr.value.trim() + "");
            }
        }

        // Dump out input HTTP request or response
        if (generalOpts.verbose) {
            println("Attempting to sign the following:");
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
        PropertiesKeyProvider propsKeyProvider = PropertiesKeyProvider.fromFile(generalOpts.configFile);

        // Create a HttpMessageSigner
        HttpMessageSigner httpMessageSigner = new HttpMessageSigner(
            new BasicStringSignerImpl(propsKeyProvider)
        );

        // Set up the Authorization header...
        AuthorizationHeader ah = authHeaderOpts.ah;

        // Pick a default partner-id and key-id if not specified
        if (ah.getPartnerId() == null && ah.getKeyId() == null) {
            String[] defaultPartner = propsKeyProvider.getDefaultPartnerKeyId();
            ah.setPartnerId(defaultPartner[0]);
            ah.setKeyId(defaultPartner[1]);
        }

        // Default to current time
        if (ah.getTimestamp() == null) {
            // HttpMessageSigner.sign() will do this for you, but we want to set it manually here so we can be sure we
            // sign the same thing that we log below.
            ah.setTimestamp(System.currentTimeMillis() / 1000);
        }

        // Create the canonical form of the message for signing, and dump it out
        CanonicalHttpMessage canonicalHttpMessage = httpMessage.canonicalize(ah);
        if (generalOpts.verbose) {
            println("Generated this ", canonicalHttpMessage.getClass().getSimpleName(), " to sign:");
            println();
            println(indent(generalOpts.indent, canonicalHttpMessage.toString(new StringBuilder()).append(ah.getTimestamp()).toString()));
            println();
        }

        // Sign and print it out
        httpMessageSigner.sign(ah, canonicalHttpMessage);

        println(authorizationHeaderName, ": ", ah);
    }

}
