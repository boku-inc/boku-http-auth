package com.boku.auth.http.exception;

/**
 * The `Authorization` header supplied in a request was invalid in and of itself, regardless of the actual credentials
 * supplied, e.g. due to invalid formatting, field validation errors, or inconsistency with the accompanying message.
 */
@SuppressWarnings("serial")
public class InvalidAuthorizationHeaderException extends AuthorizationException {

    public InvalidAuthorizationHeaderException(String message) {
        super(message);
    }

}
