import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { OAuthConfig, TokenSet } from "./types.js";
import { postJson, postForm, isTlsError, isRequestTimeout } from "./fetchPolyfill.js";

// ── PKCE helpers ────────────────────────────────────────────────

/**
 * Truncate a string for error messages.
 */
function truncate(text: string): string {
  return text.slice(0, 500);
}

/**
 * Compute the epoch seconds at which a token expires.
 */
function computeExpiresAt(expiresIn: number): number {
  return Math.floor(Date.now() / 1000) + expiresIn - 30;
}

/**
 * Base64url-encode a buffer (RFC 7515 §2).
 */
function b64url(buf: Buffer | Uint8Array): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Generate a high-entropy PKCE code verifier (RFC 7636). */
function generateCodeVerifier(): string {
  return b64url(randomBytes(32));
}

/** Derive the S256 code challenge for a verifier (RFC 7636). */
function codeChallenge(verifier: string): string {
  return b64url(createHash("sha256").update(verifier).digest());
}

// ── Config resolution & validation ─────────────────────────────

/**
 * Altium 365 **Commercial Cloud** endpoints (the non-GovCloud). Used as defaults
 * for any endpoint a caller omits from `OAuthConfig`. Override individual fields
 * for Dev/UAT or on-prem.
 */
export const COMMERCIAL_CLOUD_ENDPOINTS = {
  authEndpoint: "https://auth.altium.com/connect/authorize",
  tokenEndpoint: "https://auth.altium.com/connect/token",
  actionWaitEndpoint: "https://actionwait.altium.com/await",
  redirectUri: "https://auth.altium.com/api/AuthComplete",
} as const;

/**
 * Altium 365 **GovCloud (Production)** endpoints. Pass these as your
 * `OAuthConfig` endpoints; the library detects the Gov token endpoint and adds
 * `secure=1` to token requests automatically. See docs/govcloud.md.
 *
 * Only `authEndpoint`/`tokenEndpoint` are gov-specific. ActionWait has no
 * gov-specific DNS — both its poll endpoint (`actionWaitEndpoint`) and its
 * `AuthComplete` callback (`redirectUri`) are the **Commercial Cloud** hosts for
 * the environment tier, so both match `COMMERCIAL_CLOUD_ENDPOINTS`.
 * (A gov-host callback is not registered and won't authorize.)
 *
 * For non-production Gov tiers, override authorize/token with the dev-gov host
 * and set the ActionWait/redirect fields to that tier's commercial hosts — e.g.
 * authorize/token on `auth.dev-365-gov.altium.com`, ActionWait on
 * `actionwait.dev1.altium.com`, and `https://auth.dev1.altium.com/api/AuthComplete`.
 */
export const GOV_CLOUD_ENDPOINTS = {
  authEndpoint: "https://auth.365-gov.altium.com/connect/authorize",
  tokenEndpoint: "https://auth.365-gov.altium.com/connect/token",
  actionWaitEndpoint: "https://actionwait.altium.com/await",
  redirectUri: "https://auth.altium.com/api/AuthComplete",
} as const;

/**
 * Derive endpoints for an **AES (on-prem)** installation from its server origin.
 * Unlike Commercial/GovCloud (fixed Altium-hosted domains), AES runs on a
 * customer-controlled origin, so there is no fixed constant — call this with
 * your AES server's origin (scheme + host, plus port if non-default), e.g.
 * `createAesEndpoints("https://aes.example.com:9785")`.
 *
 * AES hosts its own ActionWait and `AuthComplete` callback (unlike Gov, which
 * shares Commercial's) and does not use `secure=1` (same rule as Commercial).
 */
export function createAesEndpoints(origin: string) {
  const base = origin.replace(/\/+$/, "");
  return {
    authEndpoint: `${base}/unifiedlogin/connect/authorize`,
    tokenEndpoint: `${base}/unifiedlogin/connect/token`,
    actionWaitEndpoint: `${base}/actionwait/await`,
    redirectUri: `${base}/unifiedlogin/api/AuthComplete`,
    scopeEndpoint: `${base}/unifiedlogin/api/ClientScopes`,
  } as const;
}

/** A config with every endpoint filled in from defaults (client auth/flags preserved). */
type EndpointConfig = Required<Pick<OAuthConfig, "authEndpoint" | "tokenEndpoint" | "actionWaitEndpoint" | "redirectUri">>;
type ResolvedConfig = OAuthConfig & EndpointConfig;

/**
 * Fill omitted endpoints from `COMMERCIAL_CLOUD_ENDPOINTS` and validate.
 * Throws if `clientId`/`scopes` are missing or any endpoint is not a valid URL.
 */
function resolveConfig(config: OAuthConfig) {
  const resolved = {
    ...config,
    authEndpoint: config.authEndpoint || COMMERCIAL_CLOUD_ENDPOINTS.authEndpoint,
    tokenEndpoint: config.tokenEndpoint || COMMERCIAL_CLOUD_ENDPOINTS.tokenEndpoint,
    actionWaitEndpoint: config.actionWaitEndpoint || COMMERCIAL_CLOUD_ENDPOINTS.actionWaitEndpoint,
    redirectUri: config.redirectUri || COMMERCIAL_CLOUD_ENDPOINTS.redirectUri,
  } satisfies ResolvedConfig;

  for (const key of ["clientId", "scopes"] as const) {
    if (!resolved[key] || resolved[key].trim() === "") {
      throw new Error(`OAuthConfig.${key} is required and must be non-empty.`);
    }
  }

  for (const key of ["authEndpoint", "tokenEndpoint", "actionWaitEndpoint", "redirectUri"] as const) {
    try {
      new URL(resolved[key]);
    } catch {
      throw new Error(`OAuthConfig.${key} is not a valid URL: "${resolved[key]}"`);
    }
  }

  return resolved;
}

// ── ActionWait long-poll ───────────────────────────────────────

/**
 * Long-poll the ActionWait endpoint for the authorization code.
 *
 * Posts { token: connectionToken } repeatedly on 408 (reconnect),
 * returns on 200 (code received) or throws on other status codes.
 */
async function pollActionWait(
  endpoint: string,
  connectionToken: string,
  signal: AbortSignal,
  timeoutMs: number,
): Promise<{ code: string; state: string }> {
  const maxRetries = 10_000; // safety net against a server that reconnects instantly

  const controller = new AbortController();
  let timedOut = false;
  const timeoutHandle = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  // Combine caller signal with our timeout.
  const abortHandler = () => controller.abort();
  signal.addEventListener("abort", abortHandler, { once: true });

  // Error for whichever signal aborted the poll (our timeout vs. the caller).
  const abortError = () =>
    new Error(timedOut ? `ActionWait poll timed out after ${timeoutMs}ms.` : "Sign-in cancelled.");

  try {
    let retries = 0;
    while (retries++ < maxRetries) {
      if (controller.signal.aborted) {
        throw abortError();
      }

      let res;
      try {
        res = await postJson(endpoint, { token: connectionToken }, controller.signal);
      } catch (err) {
        if (controller.signal.aborted) {
          throw abortError();
        }
        if (isTlsError(err)) {
          throw new Error(`ActionWait TLS error: ${err.message}`, { cause: err });
        }
        if (isRequestTimeout(err)) {
          continue;
        }
        throw err;
      }

      if (res.status === 408) {
        await Promise.resolve(); // yield before reconnecting
        continue;
      }

      if (res.status === 410) {
        throw new Error("Sign-in cancelled.");
      }

      if (res.status === 200) {
        let parsed: Record<string, unknown>;
        try {
          parsed = res.json() as Record<string, unknown>;
        } catch {
          throw new Error(`ActionWait returned 200 but body is not JSON: ${truncate(res.text())}`);
        }
        const data = parsed?.data as Record<string, unknown>;
        const oauthError = data?.error;
        if (typeof oauthError === "string" && oauthError.length > 0) {
          const desc = typeof data?.error_description === "string" ? data.error_description : "";
          throw new Error(`ActionWait sign-in failed: ${oauthError}${desc ? ` — ${desc}` : ""}`);
        }
        const code = data?.code;
        const state = data?.state;

        if (typeof code !== "string" || code.length === 0) {
          throw new Error(`ActionWait returned 200 but body is missing data.code: ${truncate(res.text())}`);
        }
        if (typeof state !== "string" || state.length === 0) {
          throw new Error(`ActionWait returned 200 but body is missing data.state: ${truncate(res.text())}`);
        }

        return { code, state };
      }

      throw new Error(`ActionWait returned ${res.status}: ${truncate(res.text())}`);
    }
    throw new Error(`ActionWait retry count exceeded ${maxRetries}.`);
  } finally {
    clearTimeout(timeoutHandle);
    signal.removeEventListener("abort", abortHandler);
  }
}

// ── Browser helpers ─────────────────────────────────────────────

/**
 * Try to open the browser with the given URL: `globalThis.open` in a browser
 * environment, or the OS-native opener command in Node (no dependency —
 * `open` on macOS, `start` on Windows, `xdg-open` elsewhere). Always logs the
 * URL too, for manual copy-and-paste if the launch fails or isn't available.
 */
function openBrowser(url: string): void {
  const opener = (globalThis as Record<string, unknown>).open as ((url: string) => void) | undefined;
  try {
    if (typeof opener === "function") {
      opener(url);
    } else {
      const platform = process.platform;
      const [command, args] = platform === "darwin"
        ? ["open", [url]]
        // Quote the URL ourselves and pass the command line verbatim: authorize URLs
        // contain `&`, which cmd.exe treats as a command separator, and Node only
        // auto-quotes arguments containing whitespace or a double quote.
        : platform === "win32"
          ? ["cmd", ["/c", "start", '""', `"${url}"`]]
          : ["xdg-open", [url]];
      spawn(command, args, { stdio: "ignore", detached: true, windowsVerbatimArguments: platform === "win32" }).unref();
    }
  } catch {
    // Fallback to console log below.
  }
  // Always log for debugging / environments without a way to launch a browser.
  console.log(`\nOpen the following URL in your browser to sign in:\n${url}`);
}

// ── Token endpoint ──────────────────────────────────────────────

/**
 * Whether a token endpoint belongs to Altium GovCloud. Gov hosts carry a "gov"
 * label (e.g. `auth.365-gov.altium.com`, `auth.dev-365-gov.altium.com`);
 * Commercial hosts (`auth.altium.com`, `auth.dev1.altium.com`) do not. Callers
 * can override detection with `OAuthConfig.secure` for non-standard hosts.
 */
function isGovTokenEndpoint(tokenEndpoint: string): boolean {
  try {
    return new URL(tokenEndpoint).hostname.toLowerCase().includes("gov");
  } catch {
    return false;
  }
}

/**
 * Fetch the list of OAuth scopes registered for a client from the
 * ClientScopes endpoint — the endpoint itself returns `[]` for an unknown
 * `clientId`. Anything else unexpected (a non-200 status, or a body that is not
 * a JSON array of strings) **throws**: an empty scope list is a meaningful
 * answer, so a failed lookup must not be reported as one.
 *
 * On Commercial/GovCloud this returns the client's static scopes (e.g.
 * `openid`, `profile`), but **no** `a365:workspace:{id}` scope — a Cloud
 * client can have access to many workspaces, so there is no single scope to
 * introspect; discover those via `desWorkspaceInfos` instead. On an AES
 * (on-prem) installation, which hosts exactly one workspace, the response
 * *does* include that workspace's `a365:workspace:{id}` scope directly — a
 * shortcut over the (also-available, but longer) `desWorkspaceInfos` round trip.
 *
 * @param scopeEndpoint the ClientScopes endpoint URL
 * @param clientId the OAuth client ID to look up scopes for
 * @returns the client's registered scopes
 * @throws if the endpoint does not answer 200 with a JSON array of scope strings
 */
export async function getClientScopes(scopeEndpoint: string, clientId: string): Promise<string[]> {
  const url = new URL(scopeEndpoint);
  url.searchParams.set("clientId", clientId);
  const response = await fetch(url.toString());
  const text = await response.text();

  if (response.status !== 200) {
    throw new Error(`ClientScopes endpoint ${response.status}: ${truncate(text)}`);
  }

  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    data = undefined; // handled by the shared error below
  }
  if (!Array.isArray(data) || data.some((scope) => typeof scope !== "string")) {
    throw new Error(`ClientScopes endpoint returned an unexpected body (expected a JSON array of strings): ${truncate(text)}`);
  }
  return data as string[];
}

/**
 * POST a form-encoded grant to the token endpoint and parse the TokenSet.
 *
 * Applies client authentication centrally: a **confidential client**
 * (`config.clientSecret` set) authenticates with an HTTP Basic header; a
 * **public client** identifies via `client_id` in the body. Sends `secure=1`
 * when the token endpoint is a Gov host (Commercial omits it) — overridable via
 * `config.secure`. Computes `expires_at` from `expires_in` (30s clock-skew buffer).
 */
async function tokenRequest(
  cfg: ResolvedConfig,
  params: Record<string, string>,
): Promise<TokenSet> {
  const body: Record<string, string> = { ...params };
  const headers: Record<string, string> = {};

  // GovCloud token requests require `secure=1`; Commercial must omit it.
  // Derived from the token endpoint host; `config.secure` forces either way.
  if (cfg.secure ?? isGovTokenEndpoint(cfg.tokenEndpoint)) {
    body.secure = "1";
  }

  if (cfg.clientSecret) {
    // Confidential client (client_secret_basic).
    const basic = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`, "utf8").toString("base64");
    headers.Authorization = `Basic ${basic}`;
  } else {
    // Public client — identify via client_id in the body.
    body.client_id = cfg.clientId;
  }

  const res = await postForm(cfg.tokenEndpoint, body, undefined, headers);

  if (res.status !== 200 && res.status !== 201) {
    let oauthError = "";
    let oauthDesc = "";
    try {
      const parsed = res.json<{ error?: unknown; error_description?: unknown }>();
      oauthError = typeof parsed?.error === "string" ? parsed.error : "";
      oauthDesc = typeof parsed?.error_description === "string" ? parsed.error_description : "";
    } catch {
      // Non-JSON error body.
    }
    const suffix = oauthDesc ? ` — ${oauthDesc}` : "";
    throw new Error(
      `Token endpoint ${res.status} ${oauthError}${suffix} (body: ${truncate(res.text())})`,
    );
  }

  let tok: TokenSet;
  try {
    tok = res.json<TokenSet>();
  } catch {
    throw new Error(`Token endpoint returned non-JSON body: ${truncate(res.text())}`);
  }

  if (tok.expires_in && !tok.expires_at) {
    tok.expires_at = computeExpiresAt(tok.expires_in);
  }
  return tok;
}

// ── Authorization request ───────────────────────────────────────

/** Options for building an authorization URL. */
export interface AuthorizationUrlOptions {
  /** Override the configured `redirectUri` (e.g. your own callback route). */
  redirectUri?: string;
  /** Provide your own `state` (defaults to a random UUID). */
  state?: string;
  /** Provide your own PKCE code verifier (defaults to a fresh random one). */
  codeVerifier?: string;
  /** Override the configured `scopes` for this request. */
  scopes?: string;
  /**
   * Controls whether the user is prompted to select a workspace during authentication
   * (login-into-workspace mode, SPEC §3.1).
   *
   * - `'strict'`: Workspace selection is **mandatory** — the user must choose a
   *   workspace before authentication can complete. The returned token is
   *   workspace-scoped, eliminating the need for a separate token-exchange step.
   * - `'optional'`: Workspace selection is presented to the user but may be skipped.
   * - `'none'` or omitted (default): Workspace selection is skipped; the flow
   *   issues a global access token as usual.
   */
  selectWorkspace?: "none" | "strict" | "optional";
}

/** A prepared authorization request: where to send the user, and what to stash. */
export interface AuthorizationRequest {
  /** The authorization URL to redirect the user's browser to. */
  url: string;
  /** The `state` value — persist it and verify it on the callback (CSRF). */
  state: string;
  /** The PKCE code verifier — persist it and pass it to `exchangeCode`. */
  codeVerifier: string;
}

function buildAuthorize(cfg: ResolvedConfig, options?: AuthorizationUrlOptions): AuthorizationRequest {
  const codeVerifier = options?.codeVerifier ?? generateCodeVerifier();
  const state = options?.state ?? crypto.randomUUID();
  const redirectUri = options?.redirectUri ?? cfg.redirectUri;

  const params = new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: redirectUri,
    scope: options?.scopes ?? cfg.scopes,
    code_challenge: codeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
  });
  // Note: `secure=1` is a token-endpoint concern only — not sent on /authorize.
  // `selectWorkspace` is only sent when explicitly requested (not 'none' or omitted).
  const sw = options?.selectWorkspace;
  if (sw === "strict" || sw === "optional") {
    params.set("selectWorkspace", sw);
  } else if (sw !== undefined && sw !== "none") {
    throw new Error(`selectWorkspace must be "strict", "optional", "none", or undefined (got: ${sw}).`);
  }

  return { url: `${cfg.authEndpoint}?${params.toString()}`, state, codeVerifier };
}

// ── Public API ──────────────────────────────────────────────────

/**
 * Build an OAuth2 authorization URL with PKCE for the standard redirect-based
 * (authorization code) flow — the flow for web/server apps that host their own
 * redirect endpoint.
 *
 * Redirect the user's browser to the returned `url`, and persist the returned
 * `state` and `codeVerifier` (e.g. in the session). On the callback, verify the
 * returned `state` matches, then call {@link exchangeCode} with the `code` and
 * the stored `codeVerifier`.
 *
 * Public and confidential clients both use PKCE; confidential clients
 * additionally authenticate with `clientSecret` at the token step.
 */
export function createAuthorizationUrl(
  config: OAuthConfig,
  options?: AuthorizationUrlOptions,
): AuthorizationRequest {
  return buildAuthorize(resolveConfig(config), options);
}

/** Parameters for exchanging an authorization code. */
export interface ExchangeCodeParams {
  /** The authorization `code` delivered to your redirect callback. */
  code: string;
  /** The PKCE code verifier from {@link createAuthorizationUrl} (recommended). */
  codeVerifier?: string;
  /** The redirect URI used in the authorize request; must match. Defaults to config. */
  redirectUri?: string;
}

/**
 * Exchange an authorization `code` (from your redirect callback) for tokens via
 * the OAuth2 `authorization_code` grant. Pair with {@link createAuthorizationUrl}
 * for the standard redirect-based flow.
 *
 * A confidential client (`config.clientSecret` set) authenticates with HTTP
 * Basic; a public client sends `client_id` and the PKCE `codeVerifier`.
 *
 * @throws Error if `code` is empty.
 */
export async function exchangeCode(
  config: OAuthConfig,
  params: ExchangeCodeParams,
): Promise<TokenSet> {
  const cfg = resolveConfig(config);

  if (!params.code) {
    throw new Error("code is required — pass the authorization code from the redirect callback.");
  }

  const body: Record<string, string> = {
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: params.redirectUri ?? cfg.redirectUri,
  };
  if (params.codeVerifier) {
    body.code_verifier = params.codeVerifier;
  }

  return tokenRequest(cfg, body);
}

export interface SignInOptions {
  /**
   * Milliseconds to wait for the ActionWait long-poll before timing out.
   * @default 180_000 (3 minutes)
   */
  timeoutMs?: number;

  /**
   * Optional signal to cancel sign-in early. When aborted, throws "Sign-in cancelled.".
   */
  signal?: AbortSignal;

  /**
   * Controls whether the user is prompted to select a workspace during authentication
   * (login-into-workspace mode, SPEC §3.1). See {@link AuthorizationUrlOptions.selectWorkspace}
   * for the full description of values.
   */
  selectWorkspace?: "none" | "strict" | "optional";

  /**
   * Override how the authorization URL is opened. Desktop integrations commonly
   * pass their host API here (for example, VS Code's `env.openExternal`). If not
   * provided, the library tries `globalThis.open(url)` and logs the URL.
   */
  openBrowser?: (url: string) => void | Promise<void>;
}

/**
 * Perform an OAuth2 PKCE sign-in using Altium's ActionWait long-poll mechanism —
 * the flow for public clients (desktop) that cannot host a redirect.
 *
 * The flow:
 * 1. Generate a PKCE verifier/challenge and a connection token (used as `state`)
 * 2. Open the browser to the authorization URL (or log it for manual copy)
 * 3. Long-poll the ActionWait endpoint until the browser callback delivers a code
 * 4. Exchange the code for tokens via the token endpoint
 * 5. Return the TokenSet
 *
 * For confidential/redirect-based apps, use {@link createAuthorizationUrl} +
 * {@link exchangeCode} instead.
 *
 * Storage is entirely the caller's concern: persist the returned TokenSet however
 * you like, and clear any prior tokens yourself when switching accounts.
 */
export async function signIn(
  config: OAuthConfig,
  options?: SignInOptions,
): Promise<TokenSet> {
  const cfg = resolveConfig(config);

  // The connection token doubles as the OAuth `state` and the ActionWait token.
  const connectionToken = crypto.randomUUID();
  const { url, codeVerifier } = buildAuthorize(cfg, {
    state: connectionToken,
    selectWorkspace: options?.selectWorkspace,
  });

  // Start long-poll BEFORE opening the browser so a fast callback can't race.
  const signal = options?.signal ?? new AbortController().signal;
  const timeoutMs = options?.timeoutMs ?? 180_000;
  const pollPromise = pollActionWait(
    cfg.actionWaitEndpoint,
    connectionToken,
    signal,
    timeoutMs,
  );

  // Open browser (or log URL for environments without globalThis.open).
  if (options?.openBrowser) {
    await options.openBrowser(url);
  } else {
    openBrowser(url);
  }

  const { code, state } = await pollPromise;

  // CSRF guard: state must match the connectionToken we generated.
  if (state !== connectionToken) {
    throw new Error("State mismatch during sign-in (possible CSRF attack).");
  }

  return tokenRequest(cfg, {
    grant_type: "authorization_code",
    code,
    redirect_uri: cfg.redirectUri,
    code_verifier: codeVerifier,
  });
}

/**
 * Exchange a base access token (from `signIn`/`exchangeCode`) for a
 * workspace-scoped token via the OAuth2 token-exchange grant. Returns the
 * resulting TokenSet.
 *
 * @param baseAccessToken The global `access_token` from a prior sign-in.
 * @throws Error if `baseAccessToken` is empty.
 */
export async function signIntoWorkspace(
  config: OAuthConfig,
  baseAccessToken: string,
  workspaceAuthId: string,
): Promise<TokenSet> {
  const cfg = resolveConfig(config);

  if (!baseAccessToken) {
    throw new Error("baseAccessToken is required — pass the access_token from a prior sign-in.");
  }

  return tokenRequest(cfg, {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: baseAccessToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    scope: `a365:workspace:${workspaceAuthId} ${cfg.scopes}`.trim(),
  });
}

/**
 * Exchange a refresh token for a fresh TokenSet via the OAuth2 `refresh_token`
 * grant. Use this when an access token has expired (see `TokenSet.expires_at`)
 * to avoid a full interactive sign-in.
 *
 * Works the same for global and workspace refresh tokens: no `scope` is sent,
 * so the grant retains the scope the refresh token was originally issued for
 * (a global token stays global; a workspace token stays workspace-scoped).
 *
 * The identity provider may or may not return a new `refresh_token`; when it
 * does (rotation), persist it and discard the old one.
 *
 * @param refreshToken The `refresh_token` from a prior TokenSet.
 * @throws Error if `refreshToken` is empty.
 */
export async function refreshToken(
  config: OAuthConfig,
  refreshToken: string,
): Promise<TokenSet> {
  const cfg = resolveConfig(config);

  if (!refreshToken) {
    throw new Error("refreshToken is required — pass the refresh_token from a prior TokenSet.");
  }

  return tokenRequest(cfg, {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
}

/**
 * Revoke a refresh token via the OAuth2 Token Revocation endpoint (RFC 7009).
 *
 * The revocation endpoint is derived from the token endpoint
 * (`/connect/token` → `/connect/revocation`). Only **refresh** tokens are
 * revoked (access tokens are short-lived and are not accepted). After revoking,
 * a subsequent {@link refreshToken} with the same token fails with
 * `invalid_grant`.
 *
 * Client authentication follows the client type: a **confidential client**
 * (`config.clientSecret` set) uses HTTP Basic; a **public client** sends
 * `client_id` in the body.
 *
 * Per RFC 7009 the endpoint returns `200` for both known and unknown tokens, so
 * a successful call is intentionally idempotent. Non-2xx responses throw.
 *
 * @param refreshTokenValue The `refresh_token` to revoke.
 * @throws Error if `refreshTokenValue` is empty, or the endpoint returns non-2xx.
 */
export async function revokeRefreshToken(
  config: OAuthConfig,
  refreshTokenValue: string,
): Promise<void> {
  const cfg = resolveConfig(config);

  if (!refreshTokenValue) {
    throw new Error("refreshToken is required — pass the refresh_token to revoke.");
  }

  const revocationEndpoint = cfg.tokenEndpoint.replace("/connect/token", "/connect/revocation");

  const body: Record<string, string> = {
    token: refreshTokenValue,
    token_type_hint: "refresh_token",
  };
  const headers: Record<string, string> = {};

  if (cfg.clientSecret) {
    // Confidential client (client_secret_basic).
    const basic = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`, "utf8").toString("base64");
    headers.Authorization = `Basic ${basic}`;
  } else {
    // Public client — identify via client_id in the body.
    body.client_id = cfg.clientId;
  }

  const res = await postForm(revocationEndpoint, body, undefined, headers);

  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Revocation endpoint ${res.status}: ${truncate(res.text())}`);
  }
}
