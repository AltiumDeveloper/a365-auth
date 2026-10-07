import { describe, it, expect, vi, beforeEach } from "vitest";
import type { OAuthConfig, TokenSet } from "./types.js";
import {
  signIn,
  signIntoWorkspace,
  refreshToken,
  revokeRefreshToken,
  createAuthorizationUrl,
  exchangeCode,
  COMMERCIAL_CLOUD_ENDPOINTS,
  GOV_CLOUD_ENDPOINTS,
  createAesEndpoints,
} from "./auth.js";

// ── Test fixtures ───────────────────────────────────────────────

const validConfig: OAuthConfig = {
  clientId: "test-client-id",
  authEndpoint: "https://auth.altium.com/connect/authorize",
  tokenEndpoint: "https://auth.altium.com/connect/token",
  scopes: "openid profile offline_access",
  actionWaitEndpoint: "https://actionwait.altium.com/await",
  redirectUri: "https://auth.altium.com/api/AuthComplete",
};

const mockTokenSet: TokenSet = {
  access_token: "mock-access-token",
  refresh_token: "mock-refresh-token",
  id_token:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIiLCJlbWFpbCI6InRlc3RAdGVzdC5jb20ifQ.mock",
  token_type: "Bearer",
  expires_in: 3600,
  scope: "openid profile offline_access",
};

// ── Helpers ─────────────────────────────────────────────────────

function mockFetchOk(tokenSet: TokenSet) {
  const text = JSON.stringify(tokenSet);
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    headers: new Map(),
    text: () => Promise.resolve(text),
    json: () => Promise.resolve(tokenSet),
  }));
}

function mockFetchError(status: number, body: string) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: false,
    status,
    headers: new Map(),
    text: () => Promise.resolve(body),
  }));
}

// ── Config validation tests ─────────────────────────────────────

describe("config validation", () => {
  it.each([["clientId"], ["scopes"]])(
    "throws when required field %s is missing",
    async (key) => {
      const badConfig = { ...validConfig };
      (badConfig as Record<string, unknown>)[key] = "";
      await expect(signIn(badConfig)).rejects.toThrow(
        `OAuthConfig.${key} is required and must be non-empty.`,
      );
    },
  );

  it.each(["authEndpoint", "tokenEndpoint", "actionWaitEndpoint", "redirectUri"])(
    "throws when %s is provided but not a valid URL",
    async (key) => {
      const badConfig = { ...validConfig, [key]: "not-a-url" };
      await expect(signIn(badConfig)).rejects.toThrow(
        `OAuthConfig.${key} is not a valid URL`,
      );
    },
  );

  it("defaults omitted endpoints to Production", async () => {
    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (url.startsWith(COMMERCIAL_CLOUD_ENDPOINTS.actionWaitEndpoint)) {
        return {
          ok: true, status: 200, headers: new Map(),
          text: async () => JSON.stringify({ data: { code: "code", state: "conn-1" } }),
        };
      }
      return {
        ok: true, status: 200, headers: new Map(),
        text: () => Promise.resolve(JSON.stringify(mockTokenSet)),
      };
    });
    const openMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("open", openMock);
    vi.stubGlobal("crypto", { ...crypto, randomUUID: () => "conn-1" });

    // Only the two required fields — endpoints come from COMMERCIAL_CLOUD_ENDPOINTS.
    await signIn({ clientId: "id", scopes: "openid profile" });

    // Browser opened at the Production authorize endpoint.
    expect(openMock.mock.calls[0][0]).toContain(COMMERCIAL_CLOUD_ENDPOINTS.authEndpoint);
    // ActionWait polled and token exchanged at Production endpoints.
    const calledUrls = fetchMock.mock.calls.map((c) => c[0] as string);
    expect(calledUrls).toContain(COMMERCIAL_CLOUD_ENDPOINTS.actionWaitEndpoint);
    expect(calledUrls).toContain(COMMERCIAL_CLOUD_ENDPOINTS.tokenEndpoint);
  });
});

// ── signIn tests ────────────────────────────────────────────────

describe("signIn", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal("open", vi.fn());
  });

  it("exchanges code for tokens and returns TokenSet with expires_at", async () => {
    const expectedConnectionToken = "conn-token-1";

    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: string) => {
      if (url.includes("await")) {
        return new Promise((resolve) =>
          resolve({
            ok: true, status: 200, headers: new Map(),
            text: async () => JSON.stringify({ data: { code: "auth-code-123", state: expectedConnectionToken } }),
          }),
        );
      }
      return new Promise((resolve) =>
        resolve({
          ok: true, status: 200, headers: new Map(),
          text: () => Promise.resolve(JSON.stringify(mockTokenSet)),
        }),
      );
    }));

    vi.stubGlobal("crypto", { ...crypto, randomUUID: () => "conn-token-1" });

    const result = await signIn(validConfig);

    expect(result.access_token).toBe("mock-access-token");
    expect(result.expires_at).toBeDefined();
    expect(typeof result.expires_at).toBe("number");
  });

  it("throws on state mismatch (CSRF)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: string) => {
      if (url.includes("await")) {
        return new Promise((resolve) =>
          resolve({
            ok: true, status: 200, headers: new Map(),
            text: async () => JSON.stringify({ data: { code: "code", state: "wrong-state" } }),
          }),
        );
      }
      return Promise.resolve({ ok: true, status: 200, headers: new Map(), text: () => Promise.resolve("{}") });
    }));

    await expect(signIn(validConfig)).rejects.toThrow(
      "State mismatch during sign-in (possible CSRF attack)",
    );
  });

  it("throws when ActionWait returns 410 (cancelled)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true, status: 410, headers: new Map(), text: () => Promise.resolve(""),
    }));
    await expect(signIn(validConfig)).rejects.toThrow("Sign-in cancelled");
  });

  it("throws when ActionWait returns non-JSON body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true, status: 200, headers: new Map(), text: () => Promise.resolve("not json"),
    }));
    await expect(signIn(validConfig)).rejects.toThrow(
      "ActionWait returned 200 but body is not JSON",
    );
  });

  it("throws when ActionWait response is missing data.code", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true, status: 200, headers: new Map(), text: () => Promise.resolve(JSON.stringify({ data: {} })),
    }));
    await expect(signIn(validConfig)).rejects.toThrow("missing data.code");
  });

  it("uses a custom browser opener while the library owns ActionWait polling", async () => {
    const openBrowser = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("crypto", { ...crypto, randomUUID: () => "hook-state" });
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: string) => {
      if (url.includes("await")) {
        return {
          ok: true,
          status: 200,
          headers: new Map(),
          text: () => Promise.resolve(JSON.stringify({ data: { code: "hook-code", state: "hook-state" } })),
        };
      }
      return {
        ok: true,
        status: 200,
        headers: new Map(),
        text: () => Promise.resolve(JSON.stringify(mockTokenSet)),
      };
    }));

    const result = await signIn(validConfig, { openBrowser, timeoutMs: 12_345 });

    expect(result.access_token).toBe("mock-access-token");
    expect(openBrowser).toHaveBeenCalledOnce();
    expect(openBrowser.mock.calls[0][0]).toContain(validConfig.authEndpoint);
    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls[0][0]).toBe(validConfig.actionWaitEndpoint);
    expect(calls[0][1].body).toBe(JSON.stringify({ token: "hook-state" }));
    const [tokenEndpoint, tokenRequest] = calls[1];
    expect(tokenEndpoint).toBe(validConfig.tokenEndpoint);
    expect(tokenRequest.body as string).toContain("code=hook-code");
  });

  it("reconnects when an ActionWait poll fails below the status layer", async () => {
    vi.stubGlobal("crypto", { ...crypto, randomUUID: () => "net-state" });
    let polls = 0;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: string) => {
      if (url.includes("await")) {
        if (polls++ === 0) {
          throw new TypeError("fetch failed", { cause: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) });
        }
        return { ok: true, status: 200, headers: new Map(), text: () => Promise.resolve(JSON.stringify({ data: { code: "c", state: "net-state" } })) };
      }
      return { ok: true, status: 200, headers: new Map(), text: () => Promise.resolve(JSON.stringify(mockTokenSet)) };
    }));

    const result = await signIn(validConfig, { timeoutMs: 2000 });

    expect(result.access_token).toBe("mock-access-token");
    expect(polls).toBe(2);
  });

  it("fails fast on a TLS failure reported through the fetch error's cause", async () => {
    const fetchMock = vi.fn().mockRejectedValue(
      new TypeError("fetch failed", { cause: Object.assign(new Error("certificate has expired"), { code: "CERT_HAS_EXPIRED" }) }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(signIn(validConfig, { timeoutMs: 2000 })).rejects.toThrow("ActionWait TLS error");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("stops polling when ActionWait never delivers a code", async () => {
    // Server keeps asking the client to reconnect (408) and never returns a code.
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      status: 408, text: () => Promise.resolve(""),
    }));

    await expect(signIn(validConfig, { timeoutMs: 50 })).rejects.toThrow(
      /ActionWait (poll timed out|retry count exceeded)/,
    );
  });
});

// ── signIntoWorkspace tests ─────────────────────────────────────

describe("signIntoWorkspace", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("exchanges base token for workspace token and returns TokenSet", async () => {
    mockFetchOk(mockTokenSet);

    const result = await signIntoWorkspace(validConfig, "stored-base-token", "workspace-abc");

    expect(result.access_token).toBe("mock-access-token");
    expect(fetch).toHaveBeenCalledWith(
      "https://auth.altium.com/connect/token",
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining("subject_token=stored-base-token"),
      }),
    );
  });

  it("includes workspace scope in the token request", async () => {
    mockFetchOk(mockTokenSet);

    await signIntoWorkspace(validConfig, "token", "workspace-abc");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    const body = calls[0][1].body as string;
    // Body is URL-encoded, so check for encoded colon (%3A).
    expect(body).toContain("a365%3Aworkspace%3Aworkspace-abc");
  });

  it("throws when baseAccessToken is empty", async () => {
    await expect(signIntoWorkspace(validConfig, "", "ws1")).rejects.toThrow(
      "baseAccessToken is required",
    );
  });

  it("handles token endpoint OAuth errors from the response body", async () => {
    mockFetchError(400, JSON.stringify({ error: "invalid_grant", error_description: "subject token expired" }));

    await expect(signIntoWorkspace(validConfig, "expired-token", "ws1")).rejects.toThrow(
      "invalid_grant — subject token expired",
    );
  });
});

// ── refreshToken tests ──────────────────────────────────────────

describe("refreshToken", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("uses the refresh_token grant and returns a TokenSet with expires_at", async () => {
    mockFetchOk(mockTokenSet);

    const result = await refreshToken(validConfig, "stored-refresh-token");

    expect(result.access_token).toBe("mock-access-token");
    expect(result.expires_at).toBeDefined();

    const body = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][1].body as string;
    expect(body).toContain("grant_type=refresh_token");
    expect(body).toContain("refresh_token=stored-refresh-token");
    // No scope is sent — the refresh retains the token's original grant
    // (global stays global, workspace stays workspace-scoped).
    expect(body).not.toContain("scope=");
  });

  it("throws when refreshToken is empty", async () => {
    await expect(refreshToken(validConfig, "")).rejects.toThrow(
      "refreshToken is required",
    );
  });

  it("surfaces OAuth errors (e.g. expired/revoked refresh token)", async () => {
    mockFetchError(400, JSON.stringify({ error: "invalid_grant", error_description: "refresh token expired" }));

    await expect(refreshToken(validConfig, "expired-refresh")).rejects.toThrow(
      "invalid_grant — refresh token expired",
    );
  });
});

// ── revokeRefreshToken tests ────────────────────────────────────

describe("revokeRefreshToken", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("POSTs to /connect/revocation with token + hint + client_id (public client)", async () => {
    mockFetchOk(mockTokenSet); // 200; the body is ignored by revoke

    await revokeRefreshToken(validConfig, "stored-refresh-token");

    const [url, opts] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("https://auth.altium.com/connect/revocation");
    expect(opts.method).toBe("POST");
    const body = opts.body as string;
    expect(body).toContain("token=stored-refresh-token");
    expect(body).toContain("token_type_hint=refresh_token");
    expect(body).toContain("client_id=test-client-id"); // public client → id in body
    expect(opts.headers.Authorization).toBeUndefined();
  });

  it("throws when refreshToken is empty", async () => {
    await expect(revokeRefreshToken(validConfig, "")).rejects.toThrow(
      "refreshToken is required",
    );
  });

  it("uses HTTP Basic and omits client_id for a confidential client", async () => {
    mockFetchOk(mockTokenSet);
    const confidential = { ...validConfig, clientSecret: "s3cret" };

    await revokeRefreshToken(confidential, "refresh-abc");

    const opts = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(opts.headers.Authorization).toBe(
      "Basic " + Buffer.from("test-client-id:s3cret", "utf8").toString("base64"),
    );
    expect(opts.body as string).not.toContain("client_id=");
  });

  it("surfaces non-2xx responses as errors", async () => {
    mockFetchError(400, "revocation failed");
    await expect(revokeRefreshToken(validConfig, "rt")).rejects.toThrow(
      "Revocation endpoint 400",
    );
  });
});

// ── createAuthorizationUrl tests (redirect-based flow) ──────────

describe("createAuthorizationUrl", () => {
  it("builds an authorize URL with PKCE and returns state + verifier", () => {
    const { url, state, codeVerifier } = createAuthorizationUrl(validConfig, {
      redirectUri: "https://my-service.example.com/callback",
      state: "my-state",
    });

    const u = new URL(url);
    expect(u.origin + u.pathname).toBe(COMMERCIAL_CLOUD_ENDPOINTS.authEndpoint);
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("client_id")).toBe(validConfig.clientId);
    expect(u.searchParams.get("redirect_uri")).toBe("https://my-service.example.com/callback");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")).toBeTruthy();
    expect(u.searchParams.get("state")).toBe("my-state");
    expect(u.searchParams.get("secure")).toBeNull();

    expect(state).toBe("my-state");
    expect(codeVerifier.length).toBeGreaterThan(20);
  });

  it("generates a random state when none is provided", () => {
    vi.stubGlobal("crypto", { ...crypto, randomUUID: () => "random-state" });
    const { state } = createAuthorizationUrl(validConfig);
    expect(state).toBe("random-state");
    vi.restoreAllMocks();
  });

  it("targets the gov host but never puts secure=1 on /authorize", () => {
    const { url } = createAuthorizationUrl({ ...validConfig, ...GOV_CLOUD_ENDPOINTS });
    const u = new URL(url);
    expect(u.origin).toBe("https://auth.365-gov.altium.com");
    // secure=1 is a token-endpoint concern only.
    expect(u.searchParams.get("secure")).toBeNull();
  });

  it("includes selectWorkspace=strict when selectWorkspace is 'strict'", () => {
    const { url } = createAuthorizationUrl(validConfig, { selectWorkspace: "strict" });
    const u = new URL(url);
    expect(u.searchParams.get("selectWorkspace")).toBe("strict");
  });

  it("includes selectWorkspace=optional when selectWorkspace is 'optional'", () => {
    const { url } = createAuthorizationUrl(validConfig, { selectWorkspace: "optional" });
    const u = new URL(url);
    expect(u.searchParams.get("selectWorkspace")).toBe("optional");
  });

  it("omits selectWorkspace when not set", () => {
    const { url } = createAuthorizationUrl(validConfig);
    expect(new URL(url).searchParams.has("selectWorkspace")).toBe(false);
  });

  it("omits selectWorkspace when set to 'none'", () => {
    const { url } = createAuthorizationUrl(validConfig, { selectWorkspace: "none" });
    expect(new URL(url).searchParams.has("selectWorkspace")).toBe(false);
  });
});

// ── exchangeCode tests (redirect-based flow) ────────────────────

describe("exchangeCode", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("exchanges an authorization code for tokens (public client)", async () => {
    mockFetchOk(mockTokenSet);

    const result = await exchangeCode(validConfig, {
      code: "auth-code",
      codeVerifier: "verifier-123",
      redirectUri: "https://my-service.example.com/callback",
    });

    expect(result.access_token).toBe("mock-access-token");
    expect(result.expires_at).toBeDefined();

    const opts = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][1];
    const body = opts.body as string;
    expect(body).toContain("grant_type=authorization_code");
    expect(body).toContain("code=auth-code");
    expect(body).toContain("code_verifier=verifier-123");
    expect(body).toContain("client_id=test-client-id"); // public client → id in body
    expect(opts.headers.Authorization).toBeUndefined(); // ...and no Basic header
  });

  it("throws when code is empty", async () => {
    await expect(exchangeCode(validConfig, { code: "" })).rejects.toThrow("code is required");
  });
});

// ── confidential client tests ───────────────────────────────────

describe("confidential client (clientSecret)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const confidential = { ...validConfig, clientSecret: "s3cret" };
  const expectedBasic = "Basic " + Buffer.from("test-client-id:s3cret", "utf8").toString("base64");

  it("authenticates with HTTP Basic and omits client_id from the body", async () => {
    mockFetchOk(mockTokenSet);

    await exchangeCode(confidential, { code: "c", codeVerifier: "v" });

    const opts = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(opts.headers.Authorization).toBe(expectedBasic);
    expect(opts.body as string).not.toContain("client_id=");
  });

  it("uses Basic auth for signIntoWorkspace", async () => {
    mockFetchOk(mockTokenSet);
    await signIntoWorkspace(confidential, "base-token", "ws1");
    const opts = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(opts.headers.Authorization).toBe(expectedBasic);
  });

  it("uses Basic auth for refreshToken", async () => {
    mockFetchOk(mockTokenSet);
    await refreshToken(confidential, "refresh-abc");
    const opts = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(opts.headers.Authorization).toBe(expectedBasic);
  });
});

// ── GovCloud tests ─────────────────────────────────────────────

describe("GovCloud", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("puts only authorize/token on the gov host; ActionWait + callback stay commercial", () => {
    expect(GOV_CLOUD_ENDPOINTS.authEndpoint).toBe("https://auth.365-gov.altium.com/connect/authorize");
    expect(GOV_CLOUD_ENDPOINTS.tokenEndpoint).toBe("https://auth.365-gov.altium.com/connect/token");
    // ActionWait has no gov DNS; poll + callback are the Commercial Cloud hosts
    // for the tier — both match COMMERCIAL_CLOUD_ENDPOINTS.
    expect(GOV_CLOUD_ENDPOINTS.actionWaitEndpoint).toBe(COMMERCIAL_CLOUD_ENDPOINTS.actionWaitEndpoint);
    expect(GOV_CLOUD_ENDPOINTS.actionWaitEndpoint).toBe("https://actionwait.altium.com/await");
    expect(GOV_CLOUD_ENDPOINTS.redirectUri).toBe(COMMERCIAL_CLOUD_ENDPOINTS.redirectUri);
    expect(GOV_CLOUD_ENDPOINTS.redirectUri).toBe("https://auth.altium.com/api/AuthComplete");
  });

  it("auto-adds secure=1 on token requests to a Gov endpoint (no flag needed)", async () => {
    mockFetchOk(mockTokenSet);

    const gov = { ...validConfig, ...GOV_CLOUD_ENDPOINTS };
    await refreshToken(gov, "r");

    const call = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toBe(GOV_CLOUD_ENDPOINTS.tokenEndpoint);
    expect(call[1].body as string).toContain("secure=1");
  });

  it("does NOT send secure=1 on token requests to a Commercial endpoint", async () => {
    mockFetchOk(mockTokenSet);

    await refreshToken(validConfig, "r"); // validConfig → commercial token endpoint

    expect((fetch as ReturnType<typeof vi.fn>).mock.calls[0][1].body as string).not.toContain("secure=1");
  });

  it("bridges Commercial→Gov: a token exchanged at the Gov endpoint gets secure=1", async () => {
    mockFetchOk(mockTokenSet);

    // A Commercial base token, exchanged for a Gov workspace at the Gov endpoint.
    const govExchange = { ...validConfig, ...GOV_CLOUD_ENDPOINTS };
    await signIntoWorkspace(govExchange, "commercial-base-token", "gov-ws");

    const call = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toBe(GOV_CLOUD_ENDPOINTS.tokenEndpoint);
    expect(call[1].body as string).toContain("secure=1");
  });

  it("honors config.secure as an explicit override of host detection", async () => {
    mockFetchOk(mockTokenSet);
    // Force OFF on a Gov endpoint...
    await refreshToken({ ...validConfig, ...GOV_CLOUD_ENDPOINTS, secure: false }, "r");
    expect((fetch as ReturnType<typeof vi.fn>).mock.calls[0][1].body as string).not.toContain("secure=1");

    vi.restoreAllMocks();
    mockFetchOk(mockTokenSet);
    // ...and force ON for a Commercial endpoint.
    await refreshToken({ ...validConfig, secure: true }, "r");
    expect((fetch as ReturnType<typeof vi.fn>).mock.calls[0][1].body as string).toContain("secure=1");
  });
});

// ── AES (on-prem) tests ──────────────────────────────────────────

describe("AES (on-prem)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const aesOrigin = "https://aes.example.com:9785";
  const aes = createAesEndpoints(aesOrigin);

  it("derives all four endpoints from the AES origin under /unifiedlogin and /actionwait", () => {
    expect(aes.authEndpoint).toBe("https://aes.example.com:9785/unifiedlogin/connect/authorize");
    expect(aes.tokenEndpoint).toBe("https://aes.example.com:9785/unifiedlogin/connect/token");
    expect(aes.actionWaitEndpoint).toBe("https://aes.example.com:9785/actionwait/await");
    expect(aes.redirectUri).toBe("https://aes.example.com:9785/unifiedlogin/api/AuthComplete");
  });

  it("strips a trailing slash from the origin before deriving endpoints", () => {
    const trimmed = createAesEndpoints(`${aesOrigin}/`);
    expect(trimmed.authEndpoint).toBe(aes.authEndpoint);
  });

  it("does NOT send secure=1 on token requests to an AES endpoint", async () => {
    mockFetchOk(mockTokenSet);

    const aesConfig = { ...validConfig, ...aes };
    await refreshToken(aesConfig, "r");

    const call = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toBe(aes.tokenEndpoint);
    expect(call[1].body as string).not.toContain("secure=1");
  });
});
