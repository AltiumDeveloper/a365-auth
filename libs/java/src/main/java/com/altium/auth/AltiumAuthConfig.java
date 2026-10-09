package com.altium.auth;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Configuration for an {@link AltiumAuthClient}. Only the client ID and scopes are required;
 * endpoints default to the Commercial Cloud.
 */
public final class AltiumAuthConfig {
    private final String clientId;
    private final String scopes;
    private final String clientSecret;
    private final AltiumEndpoints endpoints;
    private final Boolean secure;
    private final Consumer<String> openBrowser;
    private final Duration requestTimeout;

    private AltiumAuthConfig(Builder b) {
        this.clientId = b.clientId;
        this.scopes = b.scopes;
        this.clientSecret = b.clientSecret;
        this.endpoints = b.endpoints;
        this.secure = b.secure;
        this.openBrowser = b.openBrowser;
        this.requestTimeout = b.requestTimeout;
    }

    /** Starts a builder. {@code scopes} is space-delimited and should include {@code openid profile}. */
    public static Builder builder(String clientId, String scopes) {
        return new Builder(clientId, scopes);
    }

    public String clientId() {
        return clientId;
    }

    public String scopes() {
        return scopes;
    }

    /** The client secret of a confidential client; empty for a public (PKCE) client. */
    public Optional<String> clientSecret() {
        return Optional.ofNullable(clientSecret);
    }

    public AltiumEndpoints endpoints() {
        return endpoints;
    }

    /** The explicit {@code secure=1} override; empty means derive it from the token endpoint host. */
    public Optional<Boolean> secure() {
        return Optional.ofNullable(secure);
    }

    /** The callback that opens the authorize URL during {@link AltiumAuthClient#signIn()}. */
    public Optional<Consumer<String>> openBrowser() {
        return Optional.ofNullable(openBrowser);
    }

    /** Timeout for each token, revocation, and ClientScopes request. */
    public Duration requestTimeout() {
        return requestTimeout;
    }

    /** Whether the client authenticates with HTTP Basic (a secret is set) rather than PKCE alone. */
    public boolean isConfidential() {
        return clientSecret != null && !clientSecret.isEmpty();
    }

    /** Whether token requests carry {@code secure=1}: the override, else a "gov" label in the token host (SPEC §5.4). */
    public boolean useSecure() {
        if (secure != null) {
            return secure;
        }
        String host = URI.create(endpoints.tokenEndpoint()).getHost();
        return host != null && host.toLowerCase(Locale.ROOT).contains("gov");
    }

    /** Builder for {@link AltiumAuthConfig}. */
    public static final class Builder {
        private final String clientId;
        private final String scopes;
        private String clientSecret;
        private AltiumEndpoints endpoints = AltiumEndpoints.COMMERCIAL_CLOUD;
        private Boolean secure;
        private Consumer<String> openBrowser;
        private Duration requestTimeout = Duration.ofSeconds(30);

        private Builder(String clientId, String scopes) {
            this.clientId = clientId;
            this.scopes = scopes;
        }

        /** Makes this a confidential client. Never set it for a desktop (public) client. */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder endpoints(AltiumEndpoints endpoints) {
            this.endpoints = Objects.requireNonNull(endpoints, "endpoints");
            return this;
        }

        /** Forces {@code secure=1} on or off instead of deriving it from the token host. */
        public Builder secure(boolean secure) {
            this.secure = secure;
            return this;
        }

        /** Opens the authorize URL; defaults to the desktop browser, falling back to printing the URL. */
        public Builder openBrowser(Consumer<String> openBrowser) {
            this.openBrowser = openBrowser;
            return this;
        }

        public Builder requestTimeout(Duration requestTimeout) {
            this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
            return this;
        }

        /** Validates and builds the configuration. */
        public AltiumAuthConfig build() {
            requireNonBlank("clientId", clientId);
            requireNonBlank("scopes", scopes);
            requireUrl("authorizeEndpoint", endpoints.authorizeEndpoint());
            requireUrl("tokenEndpoint", endpoints.tokenEndpoint());
            requireUrl("actionWaitEndpoint", endpoints.actionWaitEndpoint());
            requireUrl("redirectUri", endpoints.redirectUri());
            if (requestTimeout.isNegative() || requestTimeout.isZero()) {
                throw new ConfigurationException("AltiumAuthConfig.requestTimeout must be positive.");
            }
            return new AltiumAuthConfig(this);
        }

        private static void requireNonBlank(String name, String value) {
            if (value == null || value.isBlank()) {
                throw new ConfigurationException("AltiumAuthConfig." + name + " is required and must be non-empty.");
            }
        }

        private static void requireUrl(String name, String value) {
            if (!isAbsoluteUrl(value)) {
                throw new ConfigurationException("AltiumEndpoints." + name + " is not a valid URL: \"" + value + "\"");
            }
        }

        private static boolean isAbsoluteUrl(String value) {
            if (value == null) {
                return false;
            }
            try {
                URI uri = new URI(value);
                return uri.getScheme() != null && uri.getHost() != null;
            } catch (URISyntaxException e) {
                return false;
            }
        }
    }
}
