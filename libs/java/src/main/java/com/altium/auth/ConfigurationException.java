package com.altium.auth;

/** Invalid configuration or argument: a missing required value or a malformed endpoint URL. */
public class ConfigurationException extends AltiumAuthException {
    private static final long serialVersionUID = 1L;

    public ConfigurationException(String message) {
        super(message);
    }
}
