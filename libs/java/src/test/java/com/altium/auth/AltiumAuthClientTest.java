package com.altium.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class AltiumAuthClientTest {
    @Test
    void codeChallengeMatchesRfc7636AppendixB() {
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                AltiumAuthClient.codeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    @Test
    void codeVerifierIsBase64UrlOf32RandomBytes() {
        String verifier = AltiumAuthClient.generateCodeVerifier();

        assertTrue(verifier.matches("[A-Za-z0-9_-]{43}"), verifier);
        assertFalse(verifier.equals(AltiumAuthClient.generateCodeVerifier()));
    }

    @Test
    void aesDerivesAllEndpointsFromItsOrigin() {
        AltiumEndpoints aes = AltiumEndpoints.aes("https://aes.example.com:9785//");

        assertEquals(new AltiumEndpoints(
                "https://aes.example.com:9785/unifiedlogin/connect/authorize",
                "https://aes.example.com:9785/unifiedlogin/connect/token",
                "https://aes.example.com:9785/actionwait/await",
                "https://aes.example.com:9785/unifiedlogin/api/AuthComplete",
                "https://aes.example.com:9785/unifiedlogin/api/ClientScopes"), aes);
    }

    @Test
    void secureFollowsTheTokenHostUnlessOverridden() {
        assertFalse(config(AltiumEndpoints.COMMERCIAL_CLOUD).build().useSecure());
        assertTrue(config(AltiumEndpoints.GOV_CLOUD).build().useSecure());
        assertFalse(config(AltiumEndpoints.aes("https://aes.example.com")).build().useSecure());
        assertFalse(config(AltiumEndpoints.GOV_CLOUD).secure(false).build().useSecure());
        assertTrue(config(AltiumEndpoints.COMMERCIAL_CLOUD).secure(true).build().useSecure());
    }

    @Test
    void buildRejectsMissingValuesAndBadUrls() {
        assertThrows(ConfigurationException.class, () -> AltiumAuthConfig.builder(" ", "openid").build());
        assertThrows(ConfigurationException.class, () -> AltiumAuthConfig.builder("c", "").build());
        assertThrows(ConfigurationException.class, () -> config(new AltiumEndpoints("not a url", "https://a/t", "https://a/w", "https://a/r")).build());
        assertThrows(ConfigurationException.class, () -> config(AltiumEndpoints.COMMERCIAL_CLOUD).requestTimeout(Duration.ZERO).build());
    }

    @Test
    void signInStartsThePollBeforeOpeningTheBrowser() {
        AtomicBoolean pollStartedFirst = new AtomicBoolean();
        FakeHttpClient http = new FakeHttpClient(call -> call.url().contains("actionwait")
                ? new FakeHttpClient.Reply(410, "")
                : new FakeHttpClient.Reply(200, "{\"access_token\":\"AT\"}"));
        AltiumAuthClient client = new AltiumAuthClient(config(AltiumEndpoints.COMMERCIAL_CLOUD)
                .openBrowser(url -> pollStartedFirst.set(!http.calls.isEmpty()))
                .build(), http);

        assertThrows(ActionWaitException.class, client::signIn);

        assertTrue(pollStartedFirst.get());
    }

    @Test
    void tokenSetToStringHidesTokens() {
        String text = new TokenSet("secret-at", "Bearer", 3600L, 1L, "secret-rt", "secret-id", "openid").toString();

        assertFalse(text.contains("secret"), text);
    }

    private static AltiumAuthConfig.Builder config(AltiumEndpoints endpoints) {
        return AltiumAuthConfig.builder("c", "openid profile").endpoints(endpoints);
    }
}
