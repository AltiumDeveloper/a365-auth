package com.altium.auth;

/** The state returned by ActionWait did not match the wait token (CSRF guard). */
public class StateMismatchException extends ActionWaitException {
    private static final long serialVersionUID = 1L;

    public StateMismatchException(String message) {
        super(message);
    }
}
