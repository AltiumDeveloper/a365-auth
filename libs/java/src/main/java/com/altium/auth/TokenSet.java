package com.altium.auth;

import java.time.Instant;
import java.util.Map;

/**
 * Token endpoint response. {@code expiresAt} is Unix epoch seconds, computed from
 * {@code expiresIn} with a 30-second clock-skew buffer when the server omits it.
 */
public record TokenSet(
        String accessToken,
        String tokenType,
        Long expiresIn,
        Long expiresAt,
        String refreshToken,
        String idToken,
        String scope) {

    private static final long CLOCK_SKEW_SECONDS = 30;

    static TokenSet fromJson(Map<?, ?> json, String rawBody, int status) {
        if (!(json.get("access_token") instanceof String accessToken) || accessToken.isEmpty()) {
            throw new OAuthException("Token endpoint response is missing access_token: " + AltiumAuthClient.truncate(rawBody), status);
        }
        Long expiresIn = json.get("expires_in") instanceof Number n ? n.longValue() : null;
        Long expiresAt = json.get("expires_at") instanceof Number n ? n.longValue() : null;
        if (expiresIn != null && expiresIn > 0 && expiresAt == null) {
            expiresAt = Instant.now().getEpochSecond() + expiresIn - CLOCK_SKEW_SECONDS;
        }
        return new TokenSet(
                accessToken,
                stringOrNull(json.get("token_type")),
                expiresIn,
                expiresAt,
                stringOrNull(json.get("refresh_token")),
                stringOrNull(json.get("id_token")),
                stringOrNull(json.get("scope")));
    }

    private static String stringOrNull(Object value) {
        return value instanceof String s ? s : null;
    }

    @Override
    public String toString() {
        return "TokenSet[tokenType=" + tokenType + ", expiresIn=" + expiresIn + ", expiresAt=" + expiresAt
                + ", scope=" + scope + ", hasRefreshToken=" + (refreshToken != null) + ", hasIdToken=" + (idToken != null) + "]";
    }
}
