// Live E2E sign-in tool for the .NET port — the .NET analog of scripts/test-signin.ts.
// Runs the real flow (ActionWait sign-in, workspace exchange, refresh, revoke) against
// a live Altium environment. Requires network + a browser; not run in the sandbox.
//
//   dotnet run --project tools/SignInTest -- [options] <clientId>
//
// Options mirror the TS harness:
//   --env prod|dev|gov|dev-gov|aes       Sign-in environment (default: prod)
//   --workspace-env prod|dev|gov|dev-gov  Endpoint for the workspace exchange (default: --env).
//                                         Not applicable to AES — an installation is a single
//                                         environment, so it signs in and exchanges on itself.
//   --aes-origin <origin>                AES server origin, e.g. https://aes.example.com:9785
//                                         (required when --env is "aes")
//   --secure | --no-secure              Force secure=1 on/off (default: auto from token host)
//   --scopes "<scopes>"                 Space-delimited scopes (default: "openid profile")
//   --workspace <authId>                Workspace to obtain a token for. Exercises both routes:
//                                         the two-trip exchange after a global sign-in (SPEC §5.2)
//                                         and the one-trip sign-in that requests
//                                         a365:workspace:{authId} directly. On AES the workspace ID
//                                         can be omitted — it is discovered from the installation's
//                                         ClientScopes endpoint (one workspace per installation).
//   --select-workspace none|strict|optional  Login-into-workspace mode at /authorize (default: none)
//                                         (not applicable to AES — no workspace-selection prompt;
//                                          request the workspace scope at sign-in instead)
//   --refresh                           Exercise refresh (implies offline_access)
//   --revoke                            Revoke the (latest) refresh token, then prove it fails
//   --userinfo                          GET /connect/userinfo and print the response
//   --authorize-url                     Print the authorize URL (+ state, verifier) and exit
//   --exchange-code <code>              Exchange an authorization code (confidential/custom redirect)
//   --code-verifier <v>                 PKCE verifier for --exchange-code
//   --redirect-uri <url>                Custom callback for authorize-url / exchange-code
//
// Env: A365_CLIENT_SECRET  → confidential client (HTTP Basic).
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;
using Altium.Auth;

const string workspaceScopePrefix = "a365:workspace:";

string? clientId = null, workspaceEnv = null;
string env = "prod", scopes = "openid profile";
string? workspace = null, code = null, codeVerifier = null, redirectUri = null, aesOrigin = null;
bool refresh = false, revoke = false, userinfo = false, authorizeUrl = false;
bool? secure = null;
var selectWorkspace = WorkspaceSelection.None;

for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--env": env = Env(args[++i]); break;
        case "--workspace-env": workspaceEnv = Env(args[++i]); break;
        case "--aes-origin": aesOrigin = args[++i]; break;
        case "--secure": secure = true; break;
        case "--no-secure": secure = false; break;
        case "--scopes": scopes = args[++i]; break;
        case "--workspace": workspace = args[++i]; break;
        case "--select-workspace": selectWorkspace = ParseSelectWorkspace(args[++i]); break;
        case "--refresh": refresh = true; break;
        case "--revoke": revoke = true; break;
        case "--userinfo": userinfo = true; break;
        case "--authorize-url": authorizeUrl = true; break;
        case "--exchange-code": code = args[++i]; break;
        case "--code-verifier": codeVerifier = args[++i]; break;
        case "--redirect-uri": redirectUri = args[++i]; break;
        default:
            if (args[i].StartsWith("--")) Fail($"unknown option {args[i]}");
            else if (clientId is not null) Fail($"unexpected argument {args[i]}");
            else clientId = args[i];
            break;
    }
}
if (clientId is null) Fail("missing <clientId>");
if (env == "aes" && aesOrigin is null) Fail("--aes-origin is required when --env is \"aes\"");
if (selectWorkspace != WorkspaceSelection.None && env == "aes")
    Fail("--select-workspace is not applicable to AES: no workspace-selection prompt (single workspace per installation)");
if ((refresh || revoke) && !scopes.Split(' ').Contains("offline_access")) scopes += " offline_access";

var clientSecret = Environment.GetEnvironmentVariable("A365_CLIENT_SECRET");
var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

AltiumAuthOptions MkOptions(string e, string? scopeOverride = null) => new()
{
    ClientId = clientId!,
    Scopes = scopeOverride ?? scopes,
    Endpoints = EndpointsFor(e, aesOrigin),
    ClientSecret = clientSecret,
    Secure = secure,
    OpenBrowser = OpenBrowser,
};

var signInOptions = MkOptions(env);
var exchangeOptions = MkOptions(workspaceEnv ?? env);

// Authorize-URL mode: print and exit (for confidential/custom-callback clients).
if (authorizeUrl)
{
    // A known workspace ID can be requested straight from /authorize (one-trip, no exchange).
    var authzOptions = workspace is null ? signInOptions : MkOptions(env, WorkspaceScopesFor(scopes, workspace));
    var authz = new AltiumAuthClient(http, authzOptions).CreateAuthorizationUrl(redirectUri, selectWorkspace: selectWorkspace);
    Console.WriteLine("=== authorize URL ===\n");
    Console.WriteLine($"redirect_uri : {redirectUri ?? signInOptions.Endpoints.RedirectUri}");
    Console.WriteLine($"scope         : {authzOptions.Scopes}");
    Console.WriteLine($"state         : {authz.State}");
    Console.WriteLine($"code_verifier : {authz.CodeVerifier}");
    Console.WriteLine($"\nOpen in a browser to sign in:\n{authz.Url}");
    return 0;
}

Console.WriteLine("=== altium-auth .NET sign-in E2E ===\n");
Console.WriteLine($"Client type   : {(clientSecret is null ? "public (PKCE)" : "confidential (HTTP Basic)")}");
Console.WriteLine($"secure=1      : {(secure is null ? "auto (from token host)" : secure.Value ? "forced on" : "forced off")}");
Console.WriteLine($"Scopes        : {signInOptions.Scopes}");
if (selectWorkspace != WorkspaceSelection.None) Console.WriteLine($"selectWorkspace: {selectWorkspace} (login-into-workspace)");
Console.WriteLine($"Sign-in ({env}) : {(code is null ? signInOptions.Endpoints.AuthorizeEndpoint : "exchange authorization code")}");
Console.WriteLine($"Token host    : {signInOptions.Endpoints.TokenEndpoint}");
if (workspace is not null) Console.WriteLine($"Exchange ({workspaceEnv ?? env}): {exchangeOptions.Endpoints.TokenEndpoint}");
if (workspace is not null && Tier(env) != Tier(workspaceEnv ?? env))
    Console.WriteLine($"\n⚠️  sign-in env '{env}' and workspace-env '{workspaceEnv}' are different environment tiers.\n" +
        "    The token exchange will likely fail (invalid_token): the Commercial→Gov bridge only works\n" +
        "    within a tier (prod↔gov, dev↔dev-gov), because the token's issuer must be trusted by the endpoint.");
Console.WriteLine();

try
{
    using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));

    // 1. Test the two-trip sign-in (global token → workspace token).
    var (currentTokens, tokenClient) = await TestTwoTripSignInAsync(cts.Token);
    // 2. Test the one-trip sign-in (workspace scope requested at sign-in). It needs its own
    //    browser round trip, and an authorization code can only be redeemed once — so it is
    //    skipped in --exchange-code mode (the code was spent on test 1).
    if (code is null) await TestOneTripSignInAsync(cts.Token);
    // 3. Test refresh if requested.
    if (refresh) currentTokens = await TestRefreshAsync(currentTokens, tokenClient, cts.Token);
    // 4. Test revocation if requested.
    if (revoke) await TestRevokeAsync(currentTokens, tokenClient, cts.Token);

    Console.WriteLine("\n✅ E2E completed.\n");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"\n❌ E2E failed: {ex.Message}\n");
    return 1;
}

// ── tests ───────────────────────────────────────────────────────

// Obtain a token via a manual authorization code (confidential/custom redirect) or the
// interactive ActionWait sign-in.
async Task<TokenSet> SignInOnceAsync(AltiumAuthClient client, CancellationToken ct) =>
    code is not null
        ? await client.ExchangeCodeAsync(code, codeVerifier, redirectUri, ct)
        : await client.SignInAsync(selectWorkspace, ct);

// AES hosts a single workspace — introspect the exact scope registered for this client via the
// ClientScopes endpoint (Cloud has no equivalent single scope to introspect; the endpoint is only
// configured for AES).
async Task<string[]?> TestScopeIntrospectionAsync(CancellationToken ct)
{
    if (signInOptions.Endpoints.ScopeEndpoint is null)
    {
        Console.WriteLine("\n⏸️  Skipping scope introspection (no endpoint configured).");
        return null;
    }

    AnnounceTest("Client scope introspection");
    var clientScopes = await AltiumAuthClient.GetClientScopesAsync(http, signInOptions.Endpoints.ScopeEndpoint, clientId!, ct);
    Console.WriteLine($"\n✅ Client scopes for {clientId} @ {signInOptions.Endpoints.ScopeEndpoint}: " +
        $"{(clientScopes.Length > 0 ? string.Join(" ", clientScopes) : "(none returned)")}");
    return clientScopes;
}

// Returns the tokens (and the client that issued them) that refresh/revoke should operate on:
// the exchanged workspace token if there was one, else the global token — always at the endpoint
// that issued it.
async Task<(TokenSet Tokens, AltiumAuthClient Client)> TestTwoTripSignInAsync(CancellationToken ct)
{
    AnnounceTest("Two-trip sign-in (global token → workspace token)");

    var signInClient = new AltiumAuthClient(http, signInOptions);
    var globalTokens = await SignInOnceAsync(signInClient, ct);
    PrintTokens("Global token:", globalTokens);

    if (userinfo) await PrintUserinfo(signInOptions, globalTokens.AccessToken);

    if (workspace is null)
    {
        Console.WriteLine("\n⏸️  Skipping workspace token exchange (no --workspace provided).");
        return (globalTokens, signInClient);
    }

    var exchangeClient = new AltiumAuthClient(http, exchangeOptions);
    var workspaceTokens = await exchangeClient.SignIntoWorkspaceAsync(globalTokens.AccessToken, workspace, ct);
    PrintTokens($"Workspace token ({workspace}) [two-trip]:", workspaceTokens);
    return (workspaceTokens, exchangeClient);
}

async Task TestOneTripSignInAsync(CancellationToken ct)
{
    // The one-trip test requests the workspace scope at sign-in on `env`'s host, so it only
    // applies when the workspace lives in that same environment. In bridge mode (e.g.
    // --workspace-env gov) the workspace is on another partition, so a direct scope request is
    // denied — skip it (the two-trip exchange above is the right path). prod and gov are the same
    // *tier* (exchange-compatible) but different *partitions*, so compare envs, not tiers.
    var oneTripExchangeEnv = workspaceEnv ?? env;
    if (oneTripExchangeEnv != env)
    {
        Console.WriteLine($"\n⏸️  Skipping one-trip sign-in: the workspace lives in '{oneTripExchangeEnv}' " +
            $"but sign-in is on '{env}'. Requesting that workspace scope at the '{env}' /authorize " +
            "endpoint is cross-partition (access_denied) — use the two-trip exchange (above).");
        return;
    }

    // The workspace scope comes from --workspace, or — on AES, where the installation hosts
    // exactly one workspace — from its ClientScopes endpoint. It is *added* to the configured
    // scopes, never substituted for them (offline_access must survive for --refresh/--revoke).
    var workspaceScope = workspace is not null
        ? workspaceScopePrefix + workspace
        : (await TestScopeIntrospectionAsync(ct))?.FirstOrDefault(s => s.StartsWith(workspaceScopePrefix, StringComparison.Ordinal));
    if (workspaceScope is null)
    {
        // Without a workspace scope this exercises the same path as the global token in
        // TestTwoTripSignInAsync, so skip it to avoid a duplicate sign-in.
        Console.WriteLine("\n⏸️  Skipping one-trip workspace sign-in (no workspace scope requested).");
        return;
    }

    AnnounceTest("One-trip sign-in (direct workspace token)");
    var oneTripOptions = MkOptions(env, $"{scopes} {workspaceScope}");
    var tokens = await SignInOnceAsync(new AltiumAuthClient(http, oneTripOptions), ct);
    PrintTokens($"Workspace token ({workspaceScope[workspaceScopePrefix.Length..]}) [one-trip]:", tokens);
    if (userinfo) await PrintUserinfo(oneTripOptions, tokens.AccessToken);
}

static async Task<TokenSet> TestRefreshAsync(TokenSet currentTokens, AltiumAuthClient tokenClient, CancellationToken ct)
{
    if (currentTokens.RefreshToken is null)
    {
        Console.WriteLine("\n⚠️  --refresh requested but no refresh_token was returned (is offline_access granted?).");
        return currentTokens;
    }

    AnnounceTest("Refresh token");
    Console.WriteLine($"\nRefreshing token: {currentTokens.RefreshToken}");
    var refreshed = await tokenClient.RefreshTokenAsync(currentTokens.RefreshToken, ct);
    PrintTokens("Refreshed token:", refreshed);
    return refreshed;
}

static async Task TestRevokeAsync(TokenSet currentTokens, AltiumAuthClient tokenClient, CancellationToken ct)
{
    if (currentTokens.RefreshToken is null)
    {
        Console.WriteLine("\n⚠️  --revoke requested but no refresh_token is available (is offline_access granted?).");
        return;
    }

    AnnounceTest("Revoke token");
    Console.WriteLine($"\nRevoking token: {currentTokens.RefreshToken}");
    await tokenClient.RevokeRefreshTokenAsync(currentTokens.RefreshToken, ct);
    Console.WriteLine("\n🔒 revocation request sent (RFC 7009: 200 for known/unknown tokens).");
    // Prove it: a refresh with the revoked token should now fail. If it still works, the test
    // has failed — fail the run rather than printing a ❌ under a green summary.
    var refreshStillWorks = false;
    try
    {
        await tokenClient.RefreshTokenAsync(currentTokens.RefreshToken, ct);
        refreshStillWorks = true;
    }
    catch (Exception ex) { Console.WriteLine($"\n✅ Refresh after revocation was rejected, as expected: {ex.Message}"); }
    if (refreshStillWorks)
        throw new InvalidOperationException("Refresh still succeeded after revocation — the revocation did not take effect.");
}

// ── helpers ─────────────────────────────────────────────────────

static string Env(string v) =>
    v is "prod" or "dev" or "gov" or "dev-gov" or "aes" ? v : FailReturn($"--env must be prod|dev|gov|dev-gov|aes (got \"{v}\")");

static WorkspaceSelection ParseSelectWorkspace(string v) => v switch
{
    "none" => WorkspaceSelection.None,
    "strict" => WorkspaceSelection.Strict,
    "optional" => WorkspaceSelection.Optional,
    _ => FailReturnWorkspace($"--select-workspace must be none|strict|optional (got \"{v}\")"),
};

static WorkspaceSelection FailReturnWorkspace(string message) { Fail(message); return WorkspaceSelection.None; }

// Environment tier: a token can only be exchanged within its own tier (prod↔gov, dev↔dev-gov).
// AES is its own tier — it never bridges to/from Commercial or Gov.
static string Tier(string env) => env switch { "prod" or "gov" => "prod", "aes" => "aes", _ => "dev" };

static string WorkspaceScopesFor(string scopes, string? workspace)
    => string.IsNullOrEmpty(workspace) ? scopes : $"{scopes} {workspaceScopePrefix}{workspace}".Trim();

static void AnnounceTest(string label) => Console.WriteLine($"\n⏺️  Testing: {label}");

static AltiumEndpoints EndpointsFor(string env, string? aesOrigin) => env switch
{
    "prod" => AltiumEndpoints.CommercialCloud,
    "gov" => AltiumEndpoints.GovCloud,
    "aes" => AltiumEndpoints.Aes(aesOrigin!), // validated present before EndpointsFor is called
    // dev / dev-gov: authorize+token on the dev host; ActionWait + AuthComplete on dev Commercial.
    "dev" => new AltiumEndpoints(
        "https://auth.dev1.altium.com/connect/authorize",
        "https://auth.dev1.altium.com/connect/token",
        "https://actionwait.dev1.altium.com/await",
        "https://auth.dev1.altium.com/api/AuthComplete"),
    "dev-gov" => new AltiumEndpoints(
        "https://auth.dev-365-gov.altium.com/connect/authorize",
        "https://auth.dev-365-gov.altium.com/connect/token",
        "https://actionwait.dev1.altium.com/await",
        "https://auth.dev1.altium.com/api/AuthComplete"),
    _ => throw new InvalidOperationException($"unknown env {env}"),
};

static void OpenBrowser(string url)
{
    try
    {
        if (OperatingSystem.IsWindows()) Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        else if (OperatingSystem.IsMacOS()) Process.Start("open", url);
        else Process.Start("xdg-open", url);
    }
    catch { /* fall through to the printed URL */ }
    Console.WriteLine($"Open the following URL in your browser to sign in:\n{url}\n");
}

static void PrintTokens(string label, TokenSet t)
{
    Console.WriteLine($"\n✅ {label}\n");
    Console.WriteLine($"  access_token : {t.AccessToken}");
    var claims = DecodeJwt(t.AccessToken);
    if (claims is { } c)
    {
        Console.WriteLine($"  ↳ iss        : {(c.TryGetProperty("iss", out var iss) ? iss.ToString() : "?")}");
        if (c.TryGetProperty("secure", out var sec)) Console.WriteLine($"  ↳ secure     : {sec}");
    }
    Console.WriteLine($"  token_type   : {t.TokenType}");
    Console.WriteLine($"  expires_at   : {t.ExpiresAt}");
    Console.WriteLine($"  scope        : {t.Scope}");
    if (!string.IsNullOrEmpty(t.RefreshToken)) Console.WriteLine($"  refresh_token: {t.RefreshToken}");
    if (!string.IsNullOrEmpty(t.IdToken) && DecodeJwt(t.IdToken) is { } idc)
    {
        var s = JsonSerializer.Serialize(idc, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine($"  id_token     : {(s.Length > 300 ? s[..300] + "..." : s)}");
    }
}

async Task PrintUserinfo(AltiumAuthOptions options, string accessToken)
{
    var url = options.Endpoints.AuthorizeEndpoint.Replace("/connect/authorize", "/connect/userinfo");
    using var req = new HttpRequestMessage(HttpMethod.Get, url);
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    var res = await http.SendAsync(req);
    Console.WriteLine($"\nℹ️  userinfo ({(int)res.StatusCode}) @ {url}:\n{await res.Content.ReadAsStringAsync()}");
}

static JsonElement? DecodeJwt(string jwt)
{
    var parts = jwt.Split('.');
    if (parts.Length != 3) return null;
    var payload = parts[1].Replace('-', '+').Replace('_', '/');
    payload += (payload.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
    try
    {
        using var doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        return doc.RootElement.Clone();
    }
    catch { return null; }
}

static void Fail(string message)
{
    Console.Error.WriteLine($"\n❌ {message}\n");
    Console.Error.WriteLine("Usage: dotnet run --project tools/SignInTest -- [options] <clientId>");
    Environment.Exit(1);
}

static string FailReturn(string message) { Fail(message); return ""; }
