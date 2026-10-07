/**
 * Conformance runner — drives the TypeScript reference implementation with the
 * language-neutral vectors in `vectors.json` and asserts the outgoing requests
 * and outcomes described there.
 *
 * This is DELIBERATELY separate from the library's own unit tests
 * (`src/index.test.ts`) and from the default `npm test`. Run it with:
 *
 *   npm run test:conformance
 *
 * It is the TypeScript SDK proving it conforms to spec/SPEC.md; other SDKs run
 * the same `vectors.json` against a mock IdP.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  signIn,
  signIntoWorkspace,
  refreshToken,
  revokeRefreshToken,
  createAuthorizationUrl,
  exchangeCode,
  getClientScopes,
} from "../../src/index";
import vectors from "../../../../spec/conformance/vectors.json";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Any = any;

afterEach(() => vi.restoreAllMocks());

/** A fetch mock that records calls and replies with a single scripted response. */
function stubFetch(reply: (url: string, opts: Any) => { status: number; body: string }) {
  const calls: Array<{ url: string; opts: Any }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, opts: Any) => {
      calls.push({ url, opts });
      const { status, body } = reply(url, opts);
      return { status, text: async () => body, json: async () => JSON.parse(body) };
    }),
  );
  return calls;
}

function bodyText(r: Any): string {
  return r?.json !== undefined ? JSON.stringify(r.json) : (r?.text ?? "");
}

function matchValue(actual: string | null, matcher: Any): void {
  if (matcher === "<any>") {
    expect(actual).not.toBeNull();
  } else if (typeof matcher === "string" && matcher.startsWith("contains:")) {
    expect(actual ?? "").toContain(matcher.slice("contains:".length));
  } else {
    expect(actual).toBe(matcher);
  }
}

// ── authorizeUrl ────────────────────────────────────────────────
describe("conformance: authorizeUrl", () => {
  for (const v of (vectors as Any).authorizeUrl) {
    it(v.id, () => {
      const authz = createAuthorizationUrl(v.config, v.options);
      const u = new URL(authz.url);
      expect(u.origin).toBe(v.expect.origin);
      expect(u.pathname).toBe(v.expect.pathname);
      for (const [k, val] of Object.entries(v.expect.query ?? {})) {
        matchValue(u.searchParams.get(k), val);
      }
      for (const k of v.expect.queryAbsent ?? []) {
        expect(u.searchParams.has(k)).toBe(false);
      }
    });
  }
});

// ── tokenRequest ────────────────────────────────────────────────
describe("conformance: tokenRequest", () => {
  for (const v of (vectors as Any).tokenRequest) {
    it(v.id, async () => {
      const calls = stubFetch(() => ({ status: v.mockResponse.status, body: bodyText(v.mockResponse) }));
      const cfg = v.config;
      const run = (): Promise<Any> => {
        switch (v.operation) {
          case "exchangeCode": return exchangeCode(cfg, v.input);
          case "signIntoWorkspace": return signIntoWorkspace(cfg, v.input.baseAccessToken, v.input.workspaceAuthId);
          case "refreshToken": return refreshToken(cfg, v.input.refreshToken);
          default: throw new Error(`unknown operation: ${v.operation}`);
        }
      };

      if (v.expectErrorContains) {
        await expect(run()).rejects.toThrow(v.expectErrorContains);
      } else {
        const result = await run();
        for (const [k, val] of Object.entries(v.expectResult ?? {})) {
          if (val === "<any>") {
            expect(result[k]).toBeDefined();
          } else if (typeof val === "string" && val.startsWith("epochWithin:")) {
            // "epochWithin:<offsetSeconds>:<toleranceSeconds>" — value ≈ now + offset.
            const [, offset, tol] = val.split(":").map(Number);
            const nowSec = Math.floor(Date.now() / 1000);
            expect(typeof result[k]).toBe("number");
            expect(Math.abs(result[k] - (nowSec + offset))).toBeLessThanOrEqual(tol);
          } else {
            expect(result[k]).toBe(val);
          }
        }
      }

      // Assert the outgoing token request.
      expect(calls.length).toBeGreaterThan(0);
      const { url, opts } = calls[0];
      const er = v.expectRequest ?? {};
      if (er.endpoint) { expect(url).toBe(er.endpoint); }
      if (er.method) { expect(opts.method).toBe(er.method); }

      const auth = opts.headers?.Authorization ?? opts.headers?.authorization;
      if (er.authorization === "none") {
        expect(auth).toBeUndefined();
      } else if (typeof er.authorization === "string" && er.authorization.startsWith("basic(")) {
        const expected = "Basic " + Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`, "utf8").toString("base64");
        expect(auth).toBe(expected);
      }

      const params = new URLSearchParams(opts.body as string);
      for (const [k, matcher] of Object.entries(er.bodyParams ?? {})) {
        matchValue(params.get(k), matcher);
      }
      for (const k of er.bodyParamsAbsent ?? []) {
        expect(params.has(k)).toBe(false);
      }
    });
  }
});

// ── actionWait ──────────────────────────────────────────────────
describe("conformance: actionWait", () => {
  for (const v of (vectors as Any).actionWait) {
    it(v.id, async () => {
      const CONN = "conn-token";
      vi.stubGlobal("crypto", { ...crypto, randomUUID: () => CONN });
      vi.stubGlobal("open", vi.fn());

      let idx = 0;
      stubFetch((url) => {
        if (url.startsWith("https://actionwait")) {
          const r = v.pollResponses[Math.min(idx, v.pollResponses.length - 1)];
          idx++;
          const body = bodyText(r).replace("<stateEchoesToken>", CONN);
          return { status: r.status, body };
        }
        // token endpoint (success path exchanges the code)
        return { status: 200, body: JSON.stringify({ access_token: "AT", token_type: "Bearer" }) };
      });

      const p = signIn({ clientId: "c", scopes: "openid profile" }, { timeoutMs: 2000 });
      if (v.expect.outcome === "code") {
        const tokens = await p;
        expect(tokens.access_token).toBe("AT"); // code flowed through to the exchange
      } else {
        await expect(p).rejects.toThrow(v.expect.errorContains);
      }
    });
  }
});

// ── revocation ──────────────────────────────────────────────────
describe("conformance: revocation", () => {
  for (const v of (vectors as Any).revocation) {
    // Behavioral-only references (no expectRequest) can't be asserted with a
    // request stub — they need a live server (revoke → refresh → invalid_grant).
    if (!v.expectRequest) {
      it.skip(`${v.id} (behavioral reference)`, () => {});
      continue;
    }
    it(v.id, async () => {
      const calls = stubFetch(() => ({ status: v.mockResponse.status, body: bodyText(v.mockResponse) }));
      const cfg = v.config;

      await revokeRefreshToken(cfg, v.input.refreshToken);

      expect(calls.length).toBeGreaterThan(0);
      const { url, opts } = calls[0];
      const er = v.expectRequest;
      if (er.endpoint) { expect(url).toBe(er.endpoint); }
      if (er.method) { expect(opts.method).toBe(er.method); }

      const auth = opts.headers?.Authorization ?? opts.headers?.authorization;
      if (er.authorization === "none") {
        expect(auth).toBeUndefined();
      } else if (typeof er.authorization === "string" && er.authorization.startsWith("basic(")) {
        const expected = "Basic " + Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`, "utf8").toString("base64");
        expect(auth).toBe(expected);
      }

      const params = new URLSearchParams(opts.body as string);
      for (const [k, matcher] of Object.entries(er.bodyParams ?? {})) {
        matchValue(params.get(k), matcher);
      }
      for (const k of er.bodyParamsAbsent ?? []) {
        expect(params.has(k)).toBe(false);
      }
    });
  }
});

// ── clientScopes ────────────────────────────────────────────────
describe("conformance: clientScopes", () => {
  for (const v of (vectors as Any).clientScopes) {
    it(v.id, async () => {
      const calls = stubFetch(() => ({ status: v.mockResponse.status, body: bodyText(v.mockResponse) }));

      if (v.expectErrorContains) {
        await expect(getClientScopes(v.input.scopeEndpoint, v.input.clientId)).rejects.toThrow(v.expectErrorContains);
      } else {
        const result = await getClientScopes(v.input.scopeEndpoint, v.input.clientId);
        expect(result).toEqual(v.expectResult);
      }

      expect(calls.length).toBeGreaterThan(0);
      const { url } = calls[0];
      const er = v.expectRequest ?? {};
      if (er.endpoint) { expect(url).toBe(er.endpoint); }
    });
  }
});

// ── userinfo (reference response shape — not a TS library function) ──
describe("conformance: userinfo (reference response shape)", () => {
  for (const v of (vectors as Any).userinfo) {
    it.skip(v.id, () => {
      /* GET /connect/userinfo → claims per schemas/userinfo.schema.json. */
    });
  }
});

// ── liveClaims (integration references — require a live server) ──
describe("conformance: liveClaims (integration references)", () => {
  for (const v of (vectors as Any).liveClaims) {
    it.skip(`${v.id} — ${v.scenario}`, () => {
      /* Golden decoded access-token claims; assert after a live sign-in. */
    });
  }
});
