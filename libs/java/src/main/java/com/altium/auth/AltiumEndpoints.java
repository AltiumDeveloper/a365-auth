package com.altium.auth;

/** The endpoints for one Altium environment. {@code scopeEndpoint} may be null. */
public record AltiumEndpoints(
        String authorizeEndpoint,
        String tokenEndpoint,
        String actionWaitEndpoint,
        String redirectUri,
        String scopeEndpoint) {

    /** Altium 365 Commercial Cloud. */
    public static final AltiumEndpoints COMMERCIAL_CLOUD = new AltiumEndpoints(
            "https://auth.altium.com/connect/authorize",
            "https://auth.altium.com/connect/token",
            "https://actionwait.altium.com/await",
            "https://auth.altium.com/api/AuthComplete");

    /** Altium 365 GovCloud. ActionWait and the AuthComplete callback stay on Commercial (SPEC §1.1, §4.2). */
    public static final AltiumEndpoints GOV_CLOUD = new AltiumEndpoints(
            "https://auth.365-gov.altium.com/connect/authorize",
            "https://auth.365-gov.altium.com/connect/token",
            "https://actionwait.altium.com/await",
            "https://auth.altium.com/api/AuthComplete");

    public AltiumEndpoints(String authorizeEndpoint, String tokenEndpoint, String actionWaitEndpoint, String redirectUri) {
        this(authorizeEndpoint, tokenEndpoint, actionWaitEndpoint, redirectUri, null);
    }

    /** Endpoints for an AES installation, derived from its origin, e.g. {@code https://aes.example.com:9785}. */
    public static AltiumEndpoints aes(String origin) {
        String base = origin.replaceAll("/+$", "");
        return new AltiumEndpoints(
                base + "/unifiedlogin/connect/authorize",
                base + "/unifiedlogin/connect/token",
                base + "/actionwait/await",
                base + "/unifiedlogin/api/AuthComplete",
                base + "/unifiedlogin/api/ClientScopes");
    }
}
