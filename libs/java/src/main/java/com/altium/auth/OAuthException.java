package com.altium.auth;

/** A token, revocation, or ClientScopes endpoint returned a non-success response. */
public class OAuthException extends AltiumAuthException {
    private static final long serialVersionUID = 1L;

    private final int status;
    private final String error;
    private final String errorDescription;

    public OAuthException(String message, int status) {
        this(message, status, "", "");
    }

    public OAuthException(String message, int status, String error, String errorDescription) {
        super(message);
        this.status = status;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    /** The HTTP status code. */
    public int getStatus() {
        return status;
    }

    /** The OAuth {@code error} code (e.g. {@code invalid_grant}), or empty if the body had none. */
    public String getError() {
        return error;
    }

    /** The OAuth {@code error_description}, or empty if the body had none. */
    public String getErrorDescription() {
        return errorDescription;
    }
}
