package com.boku.auth.http.client.exception;

import com.boku.auth.http.client.BokuAPIClientResponse;

/**
 * Specialization of {@link BokuAPIClientException} for marshalling errors.
 */
@SuppressWarnings("serial")
public class InvalidAPIEntityException extends BokuAPIClientException {

    public InvalidAPIEntityException(String message, BokuAPIClientResponse response, Throwable cause) {
        super(message, response, cause);
    }

    public InvalidAPIEntityException(String message, BokuAPIClientResponse response) {
        super(message, response);
    }

}
