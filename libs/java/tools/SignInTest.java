import com.altium.auth.AltiumAuthClient;
import com.altium.auth.AltiumAuthConfig;
import com.altium.auth.AltiumEndpoints;
import com.altium.auth.AuthorizationRequest;
import com.altium.auth.TokenSet;
import com.altium.auth.WorkspaceSelection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.time.Duration;

public final class SignInTest {
    private static final String USAGE = """
            Usage: java -cp target/classes tools/SignInTest.java [options] <clientId>

              --env prod|dev|gov|dev-gov|aes        Sign-in environment (default: prod)
              --workspace-env prod|dev|gov|dev-gov  Endpoint for the workspace exchange (default: --env)
              --aes-origin <origin>                 AES server origin (required when --env is "aes")
              --secure | --no-secure                Force secure=1 on/off (default: auto from token host)
              --scopes "<scopes>"                   Space-delimited scopes (default: "openid profile")
              --workspace <authId>                  Workspace to obtain a token for (two-trip + one-trip)
              --select-workspace none|strict|optional  Login-into-workspace mode (not applicable to AES)
              --refresh                             After sign-in, exercise refresh (implies offline_access)
              --userinfo                            After sign-in, GET /connect/userinfo and print it
              --revoke                              Revoke the (latest) refresh token, then prove it fails
              --authorize-url                       Print the authorize URL (+ state, verifier) and exit
              --redirect-uri <url>                  Callback for --authorize-url / --exchange-code
              --exchange-code <code>                Exchange an authorization code for tokens
              --code-verifier <v>                   PKCE verifier from the --authorize-url step

            Env: A365_CLIENT_SECRET  confidential client secret -> HTTP Basic (optional)
            """;
    private static final Duration SIGN_IN_TIMEOUT = Duration.ofSeconds(300);
    private static final String WORKSPACE_SCOPE_PREFIX = "a365:workspace:";
    private static final List<String> ENVS = List.of("prod", "dev", "gov", "dev-gov", "aes");

    private String clientId;
    private String env = "prod";
    private String workspaceEnv;
    private String aesOrigin;
    private Boolean secure;
    private String scopes = "openid profile";
    private String workspace;
    private WorkspaceSelection selectWorkspace;
    private boolean refresh;
    private boolean userinfo;
    private boolean revoke;
    private boolean authorizeUrl;
    private String code;
    private String codeVerifier;
    private String redirectUri;
    private final String clientSecret = System.getenv("A365_CLIENT_SECRET");

    public static void main(String[] args) {
        SignInTest test = new SignInTest();
        test.parse(args);
        System.exit(test.run());
    }

    private void parse(String[] args) {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--env" -> env = choice(args, ++i, ENVS);
                case "--workspace-env" -> workspaceEnv = choice(args, ++i, ENVS);
                case "--aes-origin" -> aesOrigin = value(args, ++i);
                case "--secure" -> secure = true;
                case "--no-secure" -> secure = false;
                case "--scopes" -> scopes = value(args, ++i);
                case "--workspace" -> workspace = value(args, ++i);
                case "--select-workspace" -> selectWorkspace =
                        WorkspaceSelection.valueOf(choice(args, ++i, List.of("none", "strict", "optional")).toUpperCase(Locale.ROOT));
                case "--refresh" -> refresh = true;
                case "--userinfo" -> userinfo = true;
                case "--revoke" -> revoke = true;
                case "--authorize-url" -> authorizeUrl = true;
                case "--exchange-code" -> code = value(args, ++i);
                case "--code-verifier" -> codeVerifier = value(args, ++i);
                case "--redirect-uri" -> redirectUri = value(args, ++i);
                default -> {
                    if (args[i].startsWith("--")) {
                        fail("unknown option " + args[i]);
                    } else if (clientId != null) {
                        fail("unexpected argument " + args[i]);
                    }
                    clientId = args[i];
                }
            }
        }
        if (clientId == null) {
            fail("missing <clientId>");
        }
        if (env.equals("aes") && aesOrigin == null) {
            fail("--aes-origin is required when --env is \"aes\".");
        }
        if (selectWorkspace != null && env.equals("aes")) {
            fail("--select-workspace is not applicable to AES (single workspace per installation).");
        }
        if ((refresh || revoke) && !Arrays.asList(scopes.split(" ")).contains("offline_access")) {
            scopes = (scopes + " offline_access").trim();
        }
    }

    private int run() {
        if (authorizeUrl) {
            runAuthorizeUrl();
            return 0;
        }
        AltiumAuthConfig signInConfig = config(env, null);
        String exchangeEnv = workspaceEnv != null ? workspaceEnv : env;
        AltiumAuthConfig exchangeConfig = config(exchangeEnv, null);

        System.out.println("=== altium-auth Java sign-in E2E test ===\n");
        System.out.println("Client type   : " + (clientSecret != null ? "confidential (HTTP Basic)" : "public (PKCE)"));
        System.out.println("secure=1      : " + (secure == null ? "auto (from token host)" : secure ? "forced on" : "forced off"));
        System.out.println("Scopes        : " + signInConfig.scopes());
        if (selectWorkspace != null && selectWorkspace != WorkspaceSelection.NONE) {
            System.out.println("selectWorkspace: " + selectWorkspace.value() + " (login-into-workspace)");
        }
        if (code != null) {
            System.out.println("Mode          : exchange authorization code (redirect_uri="
                    + (redirectUri != null ? redirectUri : signInConfig.endpoints().redirectUri()) + ")");
        } else {
            System.out.println("Sign-in (" + env + ") : " + signInConfig.endpoints().authorizeEndpoint());
            System.out.println("ActionWait    : " + signInConfig.endpoints().actionWaitEndpoint());
        }
        System.out.println("Token host    : " + signInConfig.endpoints().tokenEndpoint());
        if (workspace != null) {
            System.out.println("Exchange (" + exchangeEnv + "): " + exchangeConfig.endpoints().tokenEndpoint());
            if (!tier(env).equals(tier(exchangeEnv))) {
                System.out.println("\n⚠️  sign-in env '" + env + "' and workspace-env '" + exchangeEnv + "' are different tiers.\n"
                        + "    The exchange will likely fail (invalid_token): the Commercial→Gov bridge only works within a tier "
                        + "(prod↔gov, dev↔dev-gov).");
            }
        }

        try {
            TokenWithConfig latest = testTwoTrip(signInConfig, exchangeConfig);
            if (code == null) {
                testOneTrip(signInConfig);
            }
            if (refresh) {
                latest = new TokenWithConfig(testRefresh(latest.tokens(), latest.config()), latest.config());
            }
            if (revoke) {
                testRevoke(latest.tokens(), latest.config());
            }
            System.out.println("\n✅ E2E test passed.\n");
            return 0;
        } catch (RuntimeException e) {
            System.err.println("\n❌ E2E test failed: " + e.getMessage() + "\n");
            return 1;
        }
    }

    private record TokenWithConfig(TokenSet tokens, AltiumAuthConfig config) {
    }

    private TokenWithConfig testTwoTrip(AltiumAuthConfig signInConfig, AltiumAuthConfig exchangeConfig) {
        announce("Two-trip sign-in (global token → workspace token)");
        TokenSet global = signInOnce(new AltiumAuthClient(signInConfig));
        printTokens("Global token:", global);
        if (userinfo) {
            printUserinfo(signInConfig.endpoints().authorizeEndpoint(), global.accessToken());
        }
        if (workspace == null) {
            System.out.println("\n⏸️  Skipping workspace token exchange (no --workspace provided).");
            return new TokenWithConfig(global, signInConfig);
        }
        TokenSet ws = new AltiumAuthClient(exchangeConfig).signIntoWorkspace(global.accessToken(), workspace);
        printTokens("Workspace token (" + workspace + ") [two-trip]:", ws);
        return new TokenWithConfig(ws, exchangeConfig);
    }

    private void testOneTrip(AltiumAuthConfig signInConfig) {
        String exchangeEnv = workspaceEnv != null ? workspaceEnv : env;
        if (!exchangeEnv.equals(env)) {
            System.out.println("\n⏸️  Skipping one-trip sign-in: the workspace lives in '" + exchangeEnv + "' but sign-in is on '" + env
                    + "'. Requesting that workspace scope at the '" + env + "' /authorize endpoint is cross-partition "
                    + "(access_denied) — use the two-trip exchange (above).");
            return;
        }
        String workspaceScope = workspace != null
                ? WORKSPACE_SCOPE_PREFIX + workspace
                : testScopeIntrospection(signInConfig).stream().filter(s -> s.startsWith(WORKSPACE_SCOPE_PREFIX)).findFirst().orElse(null);
        if (workspaceScope == null) {
            System.out.println("\n⏸️  Skipping one-trip workspace sign-in (no workspace scope requested).");
            return;
        }
        announce("One-trip sign-in (direct workspace token)");
        AltiumAuthConfig oneTrip = config(env, scopes + " " + workspaceScope);
        TokenSet tokens = signInOnce(new AltiumAuthClient(oneTrip));
        printTokens("Workspace token (" + workspaceScope.substring(WORKSPACE_SCOPE_PREFIX.length()) + ") [one-trip]:", tokens);
        if (userinfo) {
            printUserinfo(oneTrip.endpoints().authorizeEndpoint(), tokens.accessToken());
        }
    }

    private List<String> testScopeIntrospection(AltiumAuthConfig signInConfig) {
        String scopeEndpoint = signInConfig.endpoints().scopeEndpoint();
        if (scopeEndpoint == null) {
            System.out.println("\n⏸️  Skipping scope introspection (no endpoint configured).");
            return List.of();
        }
        announce("Client scope introspection");
        List<String> found = AltiumAuthClient.getClientScopes(scopeEndpoint, clientId);
        System.out.println("\n✅ Client scopes for " + clientId + " @ " + scopeEndpoint + ": "
                + (found.isEmpty() ? "(none returned)" : String.join(" ", found)));
        return found;
    }

    private TokenSet testRefresh(TokenSet tokens, AltiumAuthConfig config) {
        if (tokens.refreshToken() == null) {
            System.out.println("\n⚠️  --refresh requested but no refresh_token was returned (offline_access?).");
            return tokens;
        }
        announce("Refresh token");
        System.out.println("\nRefreshing token: " + tokens.refreshToken());
        TokenSet refreshed = new AltiumAuthClient(config).refreshToken(tokens.refreshToken());
        printTokens("Refreshed token:", refreshed);
        return refreshed;
    }

    private void testRevoke(TokenSet tokens, AltiumAuthConfig config) {
        if (tokens.refreshToken() == null) {
            System.out.println("\n⚠️  --revoke requested but no refresh_token is available (offline_access?).");
            return;
        }
        AltiumAuthClient client = new AltiumAuthClient(config);
        announce("Revoke token");
        System.out.println("\nRevoking token: " + tokens.refreshToken());
        client.revokeRefreshToken(tokens.refreshToken());
        System.out.println("\n🔒 revocation request sent (RFC 7009: 200 for known/unknown tokens).");
        try {
            client.refreshToken(tokens.refreshToken());
        } catch (RuntimeException e) {
            System.out.println("\n✅ Refresh after revocation was rejected, as expected: " + e.getMessage());
            return;
        }
        throw new IllegalStateException("Refresh still worked after revocation — it did not take effect.");
    }

    private void runAuthorizeUrl() {
        AltiumAuthConfig config = config(env, workspace != null ? scopes + " " + WORKSPACE_SCOPE_PREFIX + workspace : null);
        AuthorizationRequest authz = new AltiumAuthClient(config).createAuthorizationUrl(redirectUri, null, null, selection());
        System.out.println("=== altium-auth authorize URL ===\n");
        System.out.println("redirect_uri : " + (redirectUri != null ? redirectUri : config.endpoints().redirectUri()));
        System.out.println("scope         : " + config.scopes());
        System.out.println("state         : " + authz.state());
        System.out.println("code_verifier : " + authz.codeVerifier());
        System.out.println("\nOpen this URL in a browser to sign in:\n" + authz.url());
        System.out.println("\nYour callback receives ?code=…&state=" + authz.state() + ". Then exchange it:");
        System.out.println("  java -cp target/classes tools/SignInTest.java --exchange-code <code> --code-verifier " + authz.codeVerifier()
                + (redirectUri != null ? " --redirect-uri " + redirectUri : "") + " " + clientId);
    }

    private TokenSet signInOnce(AltiumAuthClient client) {
        if (code != null) {
            return client.exchangeCode(code, codeVerifier, redirectUri);
        }
        return client.signIn(selection(), SIGN_IN_TIMEOUT);
    }

    private AltiumAuthConfig config(String environment, String scopeOverride) {
        AltiumAuthConfig.Builder builder = AltiumAuthConfig.builder(clientId, scopeOverride != null ? scopeOverride : scopes)
                .endpoints(endpoints(environment));
        if (clientSecret != null) {
            builder.clientSecret(clientSecret);
        }
        if (secure != null) {
            builder.secure(secure);
        }
        return builder.build();
    }

    private AltiumEndpoints endpoints(String environment) {
        return switch (environment) {
            case "prod" -> AltiumEndpoints.COMMERCIAL_CLOUD;
            case "gov" -> AltiumEndpoints.GOV_CLOUD;
            case "aes" -> AltiumEndpoints.aes(aesOrigin);
            case "dev" -> new AltiumEndpoints(
                    "https://auth.dev1.altium.com/connect/authorize",
                    "https://auth.dev1.altium.com/connect/token",
                    "https://actionwait.dev1.altium.com/await",
                    "https://auth.dev1.altium.com/api/AuthComplete");
            default -> new AltiumEndpoints(
                    "https://auth.dev-365-gov.altium.com/connect/authorize",
                    "https://auth.dev-365-gov.altium.com/connect/token",
                    "https://actionwait.dev1.altium.com/await",
                    "https://auth.dev1.altium.com/api/AuthComplete");
        };
    }

    private WorkspaceSelection selection() {
        return selectWorkspace != null ? selectWorkspace : WorkspaceSelection.NONE;
    }

    private static String tier(String environment) {
        return switch (environment) {
            case "prod", "gov" -> "prod";
            case "aes" -> "aes";
            default -> "dev";
        };
    }

    private static void announce(String label) {
        System.out.println("\n⏺️  Testing: " + label);
    }

    private static void printTokens(String label, TokenSet t) {
        System.out.println("\n✅ " + label + "\n");
        System.out.println("  access_token : " + t.accessToken());
        String claims = decodeJwt(t.accessToken());
        if (claims != null) {
            System.out.println("  ↳ claims     : " + claims);
        }
        System.out.println("  token_type   : " + t.tokenType());
        System.out.println("  expires_at   : " + t.expiresAt());
        System.out.println("  scope        : " + t.scope());
        if (t.refreshToken() != null) {
            System.out.println("  refresh_token: " + t.refreshToken());
        }
        if (t.idToken() != null) {
            String idClaims = decodeJwt(t.idToken());
            if (idClaims != null) {
                System.out.println("  id_token     : " + idClaims.substring(0, Math.min(300, idClaims.length())) + "...");
            }
        }
    }

    private static String decodeJwt(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return null;
        }
        try {
            return new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static void printUserinfo(String authorizeEndpoint, String accessToken) {
        String url = authorizeEndpoint.replace("/connect/authorize", "/connect/userinfo");
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Bearer " + accessToken)
                .header("User-Agent", "altium-auth-jvm")
                .build();
        try {
            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("\nℹ️  userinfo (" + response.statusCode() + ") @ " + url + ":\n" + response.body());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("userinfo request failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    private static String value(String[] args, int i) {
        if (i >= args.length) {
            fail("missing value for " + args[i - 1]);
        }
        return args[i];
    }

    private static String choice(String[] args, int i, List<String> allowed) {
        String v = value(args, i);
        if (!allowed.contains(v)) {
            fail(args[i - 1] + " must be one of " + String.join("|", allowed));
        }
        return v;
    }

    private static void fail(String message) {
        System.err.println("error: " + message + "\n\n" + USAGE);
        System.exit(2);
    }
}
