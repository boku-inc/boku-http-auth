package com.boku.auth.http.exception;

/**
 * The partner-id called out in the `Authorization` header did not exist, was not authorized to carry out the request,
 * or was not successfully authenticated as the originator of the accompanying message.
 */
@SuppressWarnings("serial")
public class AuthorizationFailedException extends AuthorizationException {

    public AuthorizationFailedException(String message) {
        super(message);
    }

}
