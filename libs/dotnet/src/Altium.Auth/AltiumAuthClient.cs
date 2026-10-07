// Altium.Auth — .NET client for Altium 365 authentication. Validates spec/SPEC.md
// by passing the shared conformance vectors. Dependency-free by design: this is a
// token-acquisition client, so it needs no JWT/JWKS validation stack; the small
// OAuth surface is hand-rolled and pinned by the conformance vectors.
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Text;

namespace Altium.Auth;

/// <inheritdoc/>
public sealed class AltiumAuthClient(HttpClient http, AltiumAuthOptions options) : IAltiumAuthClient
{
    private static string Truncate(string s) => s.Length > 500 ? s.Substring(0, 500) : s;

    private static bool HasTlsFailureInChain(Exception e)
    {
        for (var inner = e.InnerException; inner is not null; inner = inner.InnerException)
            if (inner is AuthenticationException) return true;
        return false;
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    /// <summary>Apply client auth + the Gov secure=1 rule to a token-endpoint form (SPEC §5.4).</summary>
    private HttpRequestMessage BuildTokenRequest(string endpoint, Dictionary<string, string> form)
    {
        if (options.UseSecure) form["secure"] = "1";
        var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        if (options.IsConfidential)
        {
            var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{options.ClientId}:{options.ClientSecret}"));
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        }
        else
        {
            form["client_id"] = options.ClientId;
        }
        req.Content = new FormUrlEncodedContent(form);
        return req;
    }

    private async Task<TokenSet> TokenRequestAsync(Dictionary<string, string> form, CancellationToken ct)
    {
        var res = await http.SendAsync(BuildTokenRequest(options.Endpoints.TokenEndpoint, form), ct).ConfigureAwait(false);
        var body = await Compat.ReadStringAsync(res.Content, ct).ConfigureAwait(false);
        var status = (int)res.StatusCode;

        if (status is not (200 or 201))
        {
            var e = Json.ReadOrNull<TokenErrorResponse>(body);
            var err = e?.Error ?? "";
            var desc = e?.ErrorDescription ?? "";
            var suffix = desc.Length > 0 ? $" — {desc}" : "";
            throw new InvalidOperationException($"Token endpoint {status} {err}{suffix} (body: {Truncate(body)})");
        }

        var tok = Json.ReadOrNull<TokenSet>(body);
        if (tok is null) throw new InvalidOperationException($"Token endpoint returned non-JSON body: {Truncate(body)}");

        if (tok.ExpiresIn is int ein && tok.ExpiresAt is null)
            tok.ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ein - 30; // 30s clock-skew buffer
        return tok;
    }

    /// <inheritdoc />
    public AuthorizationRequest CreateAuthorizationUrl(string? redirectUri = null, string? state = null, string? codeVerifier = null, WorkspaceSelection selectWorkspace = WorkspaceSelection.None)
    {
        var verifier = codeVerifier ?? Base64Url(Compat.RandomBytes(32));
        var challenge = Base64Url(Compat.Sha256(Encoding.ASCII.GetBytes(verifier)));
        var st = state ?? Guid.NewGuid().ToString();
        var redirect = redirectUri ?? options.Endpoints.RedirectUri;

        // NOTE: secure=1 is a token-endpoint parameter; it is NOT sent on /authorize (SPEC §5.4).
        var query = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = options.ClientId,
            ["redirect_uri"] = redirect,
            ["scope"] = options.Scopes,
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = st,
        };
        // selectWorkspace: only sent when explicitly requested — None omits it (SPEC §3.1).
        var workspaceParam = selectWorkspace switch
        {
            WorkspaceSelection.Strict => "strict",
            WorkspaceSelection.Optional => "optional",
            _ => null,
        };
        if (workspaceParam is not null)
            query["selectWorkspace"] = workspaceParam;
        var qs = string.Join("&", query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return new AuthorizationRequest($"{options.Endpoints.AuthorizeEndpoint}?{qs}", st, verifier);
    }

    /// <inheritdoc />
    public Task<TokenSet> ExchangeCodeAsync(string code, string? codeVerifier = null, string? redirectUri = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(code))
            throw new ArgumentException("code is required — pass the authorization code from the redirect callback.", nameof(code));
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri ?? options.Endpoints.RedirectUri,
        };
        if (codeVerifier is { Length: > 0 }) form["code_verifier"] = codeVerifier;
        return TokenRequestAsync(form, ct);
    }

    /// <inheritdoc />
    public Task<TokenSet> SignIntoWorkspaceAsync(string baseAccessToken, string workspaceAuthId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(baseAccessToken))
            throw new ArgumentException("baseAccessToken is required — pass the access_token from a prior sign-in.", nameof(baseAccessToken));
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = baseAccessToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["scope"] = $"a365:workspace:{workspaceAuthId} {options.Scopes}".Trim(),
        };
        return TokenRequestAsync(form, ct);
    }

    /// <inheritdoc />
    public Task<TokenSet> RefreshTokenAsync(string refreshToken, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(refreshToken))
            throw new ArgumentException("refreshToken is required — pass the refresh_token from a prior TokenSet.", nameof(refreshToken));
        // No scope sent — the grant retains the token's original scope (SPEC §5.3).
        var form = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken };
        return TokenRequestAsync(form, ct);
    }

    /// <inheritdoc />
    public Task<TokenSet> SignInAsync(CancellationToken ct = default) => SignInAsync(WorkspaceSelection.None, ct);

    /// <inheritdoc />
    public async Task<TokenSet> SignInAsync(WorkspaceSelection selectWorkspace, CancellationToken ct = default)
    {
        // The connection token doubles as the OAuth `state` and the ActionWait token (SPEC §4.1).
        var connectionToken = Guid.NewGuid().ToString();
        var authz = CreateAuthorizationUrl(state: connectionToken, selectWorkspace: selectWorkspace);

        // Start the long-poll BEFORE opening the browser so a fast callback can't race (SPEC §4.4).
        var pollTask = PollActionWaitAsync(connectionToken, ct);
        options.OpenBrowser?.Invoke(authz.Url);
        var (code, state) = await pollTask.ConfigureAwait(false);
        if (state != connectionToken)
            throw new InvalidOperationException("State mismatch during sign-in (possible CSRF attack).");

        return await ExchangeCodeAsync(code, authz.CodeVerifier, options.Endpoints.RedirectUri, ct).ConfigureAwait(false);
    }

    private async Task<(string Code, string State)> PollActionWaitAsync(string token, CancellationToken ct)
    {
        const int maxRetries = 10_000;
        for (var i = 0; i < maxRetries; i++)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, options.Endpoints.ActionWaitEndpoint)
            {
                Content = new StringContent(Json.Write(new ActionWaitRequest { Token = token }), Encoding.UTF8, "application/json"),
            };
            HttpResponseMessage res;
            try
            {
                res = await http.SendAsync(req, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException e) when (HasTlsFailureInChain(e))
            {
                throw new InvalidOperationException($"ActionWait TLS error: {e.Message}", e);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                continue;
            }

            var status = (int)res.StatusCode;

            if (status == 408) continue;                                  // normal reconnect
            if (status == 410) throw new InvalidOperationException("Sign-in cancelled.");

            var body = await Compat.ReadStringAsync(res.Content, ct).ConfigureAwait(false);
            if (status == 200)
            {
                var data = Json.ReadOrNull<ActionWaitResponse>(body)?.Data;
                if (data is null)
                    throw new InvalidOperationException($"ActionWait returned 200 but body is not JSON: {Truncate(body)}");

                // The callback may deliver an OAuth error in `data` instead of a code (SPEC §4.3).
                if (data.Error is { Length: > 0 } oauthError)
                {
                    var errDesc = data.ErrorDescription;
                    throw new InvalidOperationException(
                        $"ActionWait sign-in failed: {oauthError}{(string.IsNullOrEmpty(errDesc) ? "" : $" — {errDesc}")}");
                }

                var code = data.Code;
                var state = data.State;
                if (string.IsNullOrEmpty(code)) throw new InvalidOperationException($"ActionWait returned 200 but body is missing data.code: {Truncate(body)}");
                if (string.IsNullOrEmpty(state)) throw new InvalidOperationException($"ActionWait returned 200 but body is missing data.state: {Truncate(body)}");
                return (code!, state!);
            }
            throw new InvalidOperationException($"ActionWait returned {status}: {Truncate(body)}");
        }
        throw new InvalidOperationException($"ActionWait retry count exceeded {maxRetries}.");
    }

    /// <summary>
    /// Fetch the OAuth scopes registered for a client from the ClientScopes endpoint
    /// (<see cref="AltiumEndpoints.ScopeEndpoint"/>) — the endpoint itself returns an empty
    /// array for an unknown <paramref name="clientId"/>. Anything else unexpected (a non-200
    /// status, or a body that is not a JSON array of strings) <b>throws</b>: an empty scope list
    /// is a meaningful answer, so a failed lookup must not be reported as one.
    ///
    /// On Commercial/GovCloud this returns the client's static scopes (e.g. <c>openid</c>,
    /// <c>profile</c>), but <b>no</b> <c>a365:workspace:{id}</c> scope — a Cloud client can have
    /// access to many workspaces, so there is no single scope to introspect; discover those via
    /// <c>desWorkspaceInfos</c> instead. On an AES (on-prem) installation, which hosts exactly one
    /// workspace, the response <i>does</i> include that workspace's <c>a365:workspace:{id}</c> scope
    /// directly — a shortcut over the (also-available, but longer) <c>desWorkspaceInfos</c> round trip.
    /// </summary>
    /// <param name="http">HttpClient to issue the request with.</param>
    /// <param name="scopeEndpoint">The ClientScopes endpoint URL.</param>
    /// <param name="clientId">The OAuth client ID to look up scopes for.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">
    /// The endpoint did not answer 200 with a JSON array of scope strings.
    /// </exception>
    public static async Task<string[]> GetClientScopesAsync(HttpClient http, string scopeEndpoint, string clientId, CancellationToken ct = default)
    {
        var url = $"{scopeEndpoint}?clientId={Uri.EscapeDataString(clientId)}";
        var res = await http.GetAsync(url, ct).ConfigureAwait(false);
        var body = await Compat.ReadStringAsync(res.Content, ct).ConfigureAwait(false);
        var status = (int)res.StatusCode;

        if (status != 200) throw new InvalidOperationException($"ClientScopes endpoint {status}: {Truncate(body)}");

        return Json.ReadOrNull<string[]>(body) ?? throw new InvalidOperationException(
            $"ClientScopes endpoint returned an unexpected body (expected a JSON array of strings): {Truncate(body)}");
    }

    /// <inheritdoc />
    public async Task RevokeRefreshTokenAsync(string refreshToken, CancellationToken ct = default)
    {
        var url = options.Endpoints.TokenEndpoint.Replace("/connect/token", "/connect/revocation");
        var form = new Dictionary<string, string> { ["token"] = refreshToken, ["token_type_hint"] = "refresh_token" };
        var req = new HttpRequestMessage(HttpMethod.Post, url);
        if (options.IsConfidential)
        {
            var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{options.ClientId}:{options.ClientSecret}"));
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        }
        else
        {
            form["client_id"] = options.ClientId;
        }
        req.Content = new FormUrlEncodedContent(form);
        await http.SendAsync(req, ct).ConfigureAwait(false); // 200 with empty body (also 200 for unknown tokens)
    }
}
