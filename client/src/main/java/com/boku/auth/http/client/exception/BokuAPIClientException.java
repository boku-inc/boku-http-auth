package com.boku.auth.http.client.exception;

import java.io.IOException;

import com.boku.auth.http.client.BokuAPIClient;
import com.boku.auth.http.client.BokuAPIClientResponse;

/**
 * Thrown from {@link BokuAPIClient BokuAPIClient} while trying to execute a request or process a response.
 */
public class BokuAPIClientException extends IOException {

    private static final long serialVersionUID = 1L;

    private final BokuAPIClientResponse response;

    public BokuAPIClientException(String message, BokuAPIClientResponse response, Throwable cause) {
        super(message, cause);
        this.response = response;
    }

    public BokuAPIClientException(String message, BokuAPIClientResponse response) {
        this(message, response, null);
    }

    public BokuAPIClientException(String message, Throwable cause) {
        this(message, null, cause);
    }

    public BokuAPIClientException(String message) {
        this(message, null, null);
    }

    /**
     * Get the original returned response body
     */
    public BokuAPIClientResponse getResponse() {
        return this.response;
    }

}
