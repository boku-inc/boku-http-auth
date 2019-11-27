package com.boku.auth.http.tools.shared;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.httpsigner.HttpMessageSigner;

/**
 * Common options around what parameters should be set in the Authorization header
 */
public class AuthHeaderOptions implements Options {

    public final AuthorizationHeader ah = new AuthorizationHeader();

    public AuthHeaderOptions() {
        ah.setScheme(HttpMessageSigner.SCHEME);
    }

    @Override
    public void register(ArgvProcessor argvProcessor) {
        argvProcessor.addParam(
            "partner-id", "<ARG>",
            ah::setPartnerId,
            "Use the specified partner-id. Overrides config default."
        );
        argvProcessor.addParam(
            "key-id", "<ARG>",
            ah::setKeyId,
            "Use the specified key-id. Overrides config default."
        );
        argvProcessor.addParam(
            "timestamp", "<TS>",
            value -> ah.setTimestamp(Long.parseLong(value)),
            "Use the specified timestamp in the Authorization header. Defaults to current time."
        );
        argvProcessor.addParam(
            "sign-header", "<NAME>",
            value -> ah.getSignedHeaders().add(value),
            "Include headers with the given name in the signature. Specify multiple times for multiple headers."
        );
    }

    @Override
    public void finish(ArgvProcessor args) {
        if ((ah.getPartnerId() == null) != (ah.getKeyId() == null)) {
            args.usage("both or none of -partner-id and -key-id must be specified");
        }
    }
}
