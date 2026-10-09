package com.altium.auth;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import javax.net.ssl.SSLException;

/**
 * Altium 365 OAuth2/OIDC client: PKCE, the ActionWait desktop sign-in, workspace token exchange,
 * refresh, and revocation. Methods block; it returns tokens and leaves storing them to the caller.
 * Instances are thread-safe.
 */
public final class AltiumAuthClient {
    /** Default overall timeout for {@link #signIn()}. */
    public static final Duration DEFAULT_SIGN_IN_TIMEOUT = Duration.ofSeconds(180);

    private static final int MAX_RECONNECTS = 10_000;
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);
    // Altium's edge serves the login page instead of the token endpoint to any User-Agent containing "java".
    private static final String USER_AGENT = Optional.ofNullable(AltiumAuthClient.class.getPackage().getImplementationVersion())
            .map(v -> "altium-auth-jvm/" + v)
            .orElse("altium-auth-jvm");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final System.Logger LOG = System.getLogger("com.altium.auth");
    private static final HttpClient DEFAULT_HTTP = HttpClient.newBuilder().connectTimeout(DEFAULT_REQUEST_TIMEOUT).build();

    private final AltiumAuthConfig config;
    private final HttpClient http;

    /** Creates a client that uses a shared default {@link HttpClient}. */
    public AltiumAuthClient(AltiumAuthConfig config) {
        this(config, DEFAULT_HTTP);
    }

    /** Creates a client on your own {@link HttpClient}, e.g. one with a custom {@code SSLContext} or proxy. */
    public AltiumAuthClient(AltiumAuthConfig config, HttpClient http) {
        this.config = Objects.requireNonNull(config, "config");
        this.http = Objects.requireNonNull(http, "http");
    }

    /** Builds a PKCE authorization URL with a generated state and verifier. No network I/O. */
    public AuthorizationRequest createAuthorizationUrl() {
        return createAuthorizationUrl(null, null, null, WorkspaceSelection.NONE);
    }

    /**
     * Builds a PKCE authorization URL. Null arguments fall back to the configured redirect URI, a
     * random state, and a random verifier. No network I/O.
     */
    public AuthorizationRequest createAuthorizationUrl(String redirectUri, String state, String codeVerifier, WorkspaceSelection selectWorkspace) {
        String verifier = isEmpty(codeVerifier) ? generateCodeVerifier() : codeVerifier;
        String chosenState = isEmpty(state) ? UUID.randomUUID().toString() : state;
        Map<String, String> query = new LinkedHashMap<>();
        query.put("response_type", "code");
        query.put("client_id", config.clientId());
        query.put("redirect_uri", isEmpty(redirectUri) ? config.endpoints().redirectUri() : redirectUri);
        query.put("scope", config.scopes());
        query.put("code_challenge", codeChallenge(verifier));
        query.put("code_challenge_method", "S256");
        query.put("state", chosenState);
        if (selectWorkspace != null && selectWorkspace != WorkspaceSelection.NONE) {
            query.put("selectWorkspace", selectWorkspace.value());
        }
        String url = config.endpoints().authorizeEndpoint() + "?" + formEncode(query);
        return new AuthorizationRequest(url, chosenState, verifier);
    }

    /** Exchanges an authorization code for tokens, without a PKCE verifier and with the configured redirect URI. */
    public TokenSet exchangeCode(String code) {
        return exchangeCode(code, null, null);
    }

    /** Exchanges an authorization code for tokens ({@code authorization_code} grant). Null arguments are omitted or defaulted. */
    public TokenSet exchangeCode(String code, String codeVerifier, String redirectUri) {
        if (isEmpty(code)) {
            throw new ConfigurationException("code is required — pass the authorization code from the redirect callback.");
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("grant_type", "authorization_code");
        body.put("code", code);
        body.put("redirect_uri", isEmpty(redirectUri) ? config.endpoints().redirectUri() : redirectUri);
        if (!isEmpty(codeVerifier)) {
            body.put("code_verifier", codeVerifier);
        }
        return tokenRequest(body);
    }

    /** Exchanges a global access token for a workspace-scoped token (RFC 8693). */
    public TokenSet signIntoWorkspace(String baseAccessToken, String workspaceAuthId) {
        if (isEmpty(baseAccessToken)) {
            throw new ConfigurationException("baseAccessToken is required — pass the access_token from a prior sign-in.");
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        body.put("subject_token", baseAccessToken);
        body.put("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        body.put("scope", ("a365:workspace:" + workspaceAuthId + " " + config.scopes()).trim());
        return tokenRequest(body);
    }

    /** Refreshes an access token. No scope is sent, so the token keeps its original scope (SPEC §5.3). */
    public TokenSet refreshToken(String refreshToken) {
        if (isEmpty(refreshToken)) {
            throw new ConfigurationException("refreshToken is required — pass the refresh_token from a prior TokenSet.");
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("grant_type", "refresh_token");
        body.put("refresh_token", refreshToken);
        return tokenRequest(body);
    }

    /** Revokes a refresh token (RFC 7009). Idempotent: the server answers 200 for unknown tokens too. */
    public void revokeRefreshToken(String refreshToken) {
        if (isEmpty(refreshToken)) {
            throw new ConfigurationException("refreshToken is required — pass the refresh_token to revoke.");
        }
        String endpoint = config.endpoints().tokenEndpoint().replace("/connect/token", "/connect/revocation");
        Map<String, String> body = new LinkedHashMap<>();
        body.put("token", refreshToken);
        body.put("token_type_hint", "refresh_token");
        HttpResponse<String> response = send(http, formPost(endpoint, body));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new OAuthException("Revocation endpoint " + response.statusCode() + ": " + truncate(response.body()), response.statusCode());
        }
    }

    /** Fetches the scopes registered for a client from {@code {base}/api/ClientScopes}, on the shared default {@link HttpClient}. */
    public static List<String> getClientScopes(String scopeEndpoint, String clientId) {
        return getClientScopes(DEFAULT_HTTP, scopeEndpoint, clientId);
    }

    /**
     * Fetches the scopes registered for a client. Only AES returns an {@code a365:workspace:{id}}
     * scope. A non-200 status or a body that is not a JSON array of strings throws, because an
     * empty list means "this client has no scopes".
     */
    public static List<String> getClientScopes(HttpClient http, String scopeEndpoint, String clientId) {
        String separator = scopeEndpoint.contains("?") ? "&" : "?";
        HttpRequest request = HttpRequest.newBuilder(URI.create(scopeEndpoint + separator + "clientId=" + encode(clientId)))
                .GET()
                .header("User-Agent", USER_AGENT)
                .timeout(DEFAULT_REQUEST_TIMEOUT)
                .build();
        HttpResponse<String> response = send(http, request);
        if (response.statusCode() != 200) {
            throw new OAuthException("ClientScopes endpoint " + response.statusCode() + ": " + truncate(response.body()), response.statusCode());
        }
        if (Json.parseOrNull(response.body()) instanceof List<?> items && items.stream().allMatch(String.class::isInstance)) {
            return items.stream().map(String.class::cast).toList();
        }
        throw new OAuthException("ClientScopes endpoint returned an unexpected body (expected a JSON array of strings): "
                + truncate(response.body()), response.statusCode());
    }

    /** Interactive public-client sign-in via ActionWait, with the default timeout. */
    public TokenSet signIn() {
        return signIn(WorkspaceSelection.NONE, DEFAULT_SIGN_IN_TIMEOUT);
    }

    /** Interactive public-client sign-in via ActionWait, with the default timeout. */
    public TokenSet signIn(WorkspaceSelection selectWorkspace) {
        return signIn(selectWorkspace, DEFAULT_SIGN_IN_TIMEOUT);
    }

    /**
     * Interactive public-client sign-in via ActionWait: opens the browser, long-polls for the
     * callback, verifies the state (CSRF), and exchanges the code. Interrupting the calling thread
     * aborts the poll with a {@link TransportException}.
     */
    public TokenSet signIn(WorkspaceSelection selectWorkspace, Duration timeout) {
        if (timeout.isNegative() || timeout.isZero()) {
            throw new ConfigurationException("timeout must be positive.");
        }
        String waitToken = UUID.randomUUID().toString();
        AuthorizationRequest authorization = createAuthorizationUrl(null, waitToken, null, selectWorkspace);
        long deadline = System.nanoTime() + timeout.toNanos();
        CompletableFuture<HttpResponse<String>> firstPoll = http.sendAsync(pollRequest(waitToken, timeout), HttpResponse.BodyHandlers.ofString());
        openBrowser(authorization.url());
        String code = pollActionWait(waitToken, deadline, timeout, firstPoll);

        Map<String, String> body = new LinkedHashMap<>();
        body.put("grant_type", "authorization_code");
        body.put("code", code);
        body.put("redirect_uri", config.endpoints().redirectUri());
        body.put("code_verifier", authorization.codeVerifier());
        return tokenRequest(body);
    }

    private String pollActionWait(String waitToken, long deadline, Duration timeout, CompletableFuture<HttpResponse<String>> firstPoll) {
        CompletableFuture<HttpResponse<String>> pending = firstPoll;
        for (int attempt = 0; attempt < MAX_RECONNECTS; attempt++) {
            if (pending == null) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    throw new ActionWaitException("ActionWait poll timed out after " + timeout.toSeconds() + "s.");
                }
                pending = http.sendAsync(pollRequest(waitToken, Duration.ofNanos(remaining)), HttpResponse.BodyHandlers.ofString());
            }
            HttpResponse<String> response;
            try {
                response = await(pending);
            } catch (HttpConnectTimeoutException e) {
                throw new TransportException("Network error requesting " + config.endpoints().actionWaitEndpoint() + ": " + e, e);
            } catch (HttpTimeoutException e) {
                pending = null;
                continue;
            } catch (IOException e) {
                if (isTlsFailure(e)) {
                    throw new ActionWaitException("ActionWait TLS error: " + e.getMessage(), e);
                }
                throw new TransportException("Network error requesting " + config.endpoints().actionWaitEndpoint() + ": " + e, e);
            }
            pending = null;

            int status = response.statusCode();
            if (status == 408) {
                continue;
            }
            if (status == 410) {
                throw new ActionWaitException("Sign-in cancelled.");
            }
            if (status == 200) {
                return codeFromActionWait(response.body(), waitToken);
            }
            throw new ActionWaitException("ActionWait returned " + status + ": " + truncate(response.body()));
        }
        throw new ActionWaitException("ActionWait retry count exceeded " + MAX_RECONNECTS + ".");
    }

    private static String codeFromActionWait(String body, String waitToken) {
        Object parsed = Json.parseOrNull(body);
        if (!(parsed instanceof Map<?, ?> envelope)) {
            throw new ActionWaitException("ActionWait returned 200 but body is not JSON: " + truncate(body));
        }
        Map<?, ?> data = envelope.get("data") instanceof Map<?, ?> m ? m : Map.of();
        if (data.get("error") instanceof String error && !error.isEmpty()) {
            String suffix = data.get("error_description") instanceof String d && !d.isEmpty() ? " — " + d : "";
            throw new ActionWaitException("ActionWait sign-in failed: " + error + suffix);
        }
        if (!(data.get("code") instanceof String code) || code.isEmpty()) {
            throw new ActionWaitException("ActionWait returned 200 but body is missing data.code: " + truncate(body));
        }
        if (!(data.get("state") instanceof String state) || state.isEmpty()) {
            throw new ActionWaitException("ActionWait returned 200 but body is missing data.state: " + truncate(body));
        }
        if (!state.equals(waitToken)) {
            throw new StateMismatchException("State mismatch during sign-in (possible CSRF attack).");
        }
        return code;
    }

    private HttpRequest pollRequest(String waitToken, Duration timeout) {
        return HttpRequest.newBuilder(URI.create(config.endpoints().actionWaitEndpoint()))
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(Map.of("token", waitToken))))
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .timeout(timeout)
                .build();
    }

    private TokenSet tokenRequest(Map<String, String> params) {
        Map<String, String> body = new LinkedHashMap<>(params);
        if (config.useSecure()) {
            body.put("secure", "1");
        }
        HttpResponse<String> response = send(http, formPost(config.endpoints().tokenEndpoint(), body));
        int status = response.statusCode();
        Object parsed = Json.parseOrNull(response.body());
        if (status != 200 && status != 201) {
            Map<?, ?> json = parsed instanceof Map<?, ?> m ? m : Map.of();
            String error = json.get("error") instanceof String s ? s : "";
            String description = json.get("error_description") instanceof String s ? s : "";
            String suffix = description.isEmpty() ? "" : " — " + description;
            throw new OAuthException("Token endpoint " + status + " " + error + suffix + " (body: " + truncate(response.body()) + ")",
                    status, error, description);
        }
        if (!(parsed instanceof Map<?, ?> json)) {
            throw new OAuthException("Token endpoint returned non-JSON body: " + truncate(response.body()), status);
        }
        return TokenSet.fromJson(json, response.body(), status);
    }

    private HttpRequest formPost(String endpoint, Map<String, String> body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(endpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("User-Agent", USER_AGENT)
                .timeout(config.requestTimeout());
        if (config.isConfidential()) {
            String credentials = config.clientId() + ":" + config.clientSecret().orElseThrow();
            request.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
        } else {
            body.put("client_id", config.clientId());
        }
        return request.POST(HttpRequest.BodyPublishers.ofString(formEncode(body))).build();
    }

    private void openBrowser(String url) {
        Optional<Consumer<String>> custom = config.openBrowser();
        try {
            if (custom.isPresent()) {
                custom.get().accept(url);
                return;
            }
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
            } else {
                new ProcessBuilder("xdg-open", url)
                        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                        .redirectError(ProcessBuilder.Redirect.DISCARD)
                        .start();
            }
        } catch (Exception | LinkageError e) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to open the browser automatically", e);
        }
        System.out.println("\nOpen the following URL in your browser to sign in:\n" + url);
    }

    private static HttpResponse<String> send(HttpClient http, HttpRequest request) {
        try {
            return await(http.sendAsync(request, HttpResponse.BodyHandlers.ofString()));
        } catch (IOException e) {
            if (isTlsFailure(e)) {
                throw new TlsException("TLS error requesting " + request.uri() + ": " + e.getMessage(), e);
            }
            throw new TransportException("Network error requesting " + request.uri() + ": " + e, e);
        }
    }

    private static HttpResponse<String> await(CompletableFuture<HttpResponse<String>> response) throws IOException {
        try {
            return response.get();
        } catch (InterruptedException e) {
            response.cancel(true);
            Thread.currentThread().interrupt();
            throw new TransportException("Interrupted while waiting for a response.", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException io) {
                throw io;
            }
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw new TransportException("Request failed: " + cause, cause);
        }
    }

    private static boolean isTlsFailure(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return true;
            }
        }
        return false;
    }

    static String generateCodeVerifier() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String codeChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required on every Java platform", e);
        }
    }

    static String truncate(String text) {
        return text.length() > 500 ? text.substring(0, 500) : text;
    }

    private static String formEncode(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }
}
