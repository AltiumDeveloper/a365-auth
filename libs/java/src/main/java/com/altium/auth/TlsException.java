package com.altium.auth;

/** A TLS or certificate failure. */
public class TlsException extends TransportException {
    private static final long serialVersionUID = 1L;

    public TlsException(String message, Throwable cause) {
        super(message, cause);
    }
}
