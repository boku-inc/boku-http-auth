package com.boku.auth.http.exception;

/**
 * Thrown when signing.<br>
 * Since when signing the app itself chooses the credentials to use, this happening is usually indicative of some kind
 * of configuration problem we don't want to explicitly handle in code.
 */
@SuppressWarnings("serial")
public class InvalidApplicationSuppliedAuthorizationHeaderException extends RuntimeException {

    public InvalidApplicationSuppliedAuthorizationHeaderException(String message, InvalidAuthorizationHeaderException cause) {
        super(message, cause);
    }

}
