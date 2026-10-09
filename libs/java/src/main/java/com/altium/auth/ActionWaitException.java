package com.altium.auth;

/** The ActionWait long poll failed, timed out, or was cancelled. */
public class ActionWaitException extends AltiumAuthException {
    private static final long serialVersionUID = 1L;

    public ActionWaitException(String message) {
        super(message);
    }

    public ActionWaitException(String message, Throwable cause) {
        super(message, cause);
    }
}
