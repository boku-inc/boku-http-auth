package com.boku.auth.http.exception;

/**
 * Base exception for errors surfaced while doing authentication and authorization checks from within
 * boku-http-auth.
 */
@SuppressWarnings("serial")
public abstract class AuthorizationException extends Exception {

    public AuthorizationException(String message) {
        super(message);
    }

}
