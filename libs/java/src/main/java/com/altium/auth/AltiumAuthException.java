package com.altium.auth;

/** Base class for every exception thrown by this library. */
public class AltiumAuthException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public AltiumAuthException(String message) {
        super(message);
    }

    public AltiumAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
