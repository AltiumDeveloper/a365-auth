package com.altium.auth;

/** A network-level failure, or an interrupt while waiting for a response. */
public class TransportException extends AltiumAuthException {
    private static final long serialVersionUID = 1L;

    public TransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
