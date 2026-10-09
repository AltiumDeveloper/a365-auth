package com.altium.auth;

/**
 * A prepared authorization request: the URL to send the user to, plus the state and PKCE
 * verifier to keep for the callback and the code exchange.
 */
public record AuthorizationRequest(String url, String state, String codeVerifier) {
}
