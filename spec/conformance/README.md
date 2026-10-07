# Conformance vectors

Language-neutral test vectors that pin down the Altium-specific behavior in
[SPEC.md](https://github.com/AltiumDeveloper/altium-auth/blob/main/spec/SPEC.md).
Every SDK (TS, .NET, Java, …) should run these against
a mock IdP and assert the same outgoing requests and outcomes, so all
implementations stay consistent.

Source of truth: `../../src/index.test.ts` (unit behavior) and the live
Commercial/Gov/Dev captures (Tests A/B/C + dev confidential) recorded during
validation.

## File

- `vectors.json` — the vectors, grouped by category.

## Categories & matchers

Values in `expect` blocks may be literals or one of these matchers (strings):

- `"<any>"` — key/param must be present, any value.
- `"contains:<substr>"` — string value must contain `<substr>`.
- `"basic(clientId:clientSecret)"` — an `Authorization` header of `Basic base64(clientId ":" clientSecret)`.
- `"none"` — (for `authorization`) the header must be absent.
- `"epochWithin:<offset>:<tol>"` — (for a numeric result field like `expires_at`) the value must be within `<tol>` seconds of `now + <offset>`.

### `authorizeUrl`
Input: `config` + `options` (a fixed `codeVerifier`/`state` make it deterministic).
`expect`: `origin`, `pathname`, `query` (exact key→value), `queryAbsent` (keys that must not appear).

### `tokenRequest`
Input: `operation` (`exchangeCode` | `signIntoWorkspace` | `refreshToken`), `config`, `input`.
`expectRequest`: `endpoint`, `method`, `authorization`, `bodyParams` (key→value/matcher), `bodyParamsAbsent`.
Then either `mockResponse` + `expectResult`, or `mockResponse` + `expectErrorContains`.

### `actionWait`
Input: `pollResponses` (an ordered list the mock returns to successive `POST /await` calls).
`expect`: `outcome` (`code` | `errorContains`) — verifies `408`=reconnect, `410`=terminal, `200` parse rules.

### `liveClaims`
Golden decoded **access-token claims** from real runs — integration references (assert after decoding a token obtained from the live server for that scenario).

### `clientScopes`
Input: `input` (`scopeEndpoint`, `clientId`). Drives `getClientScopes`/`GetClientScopesAsync`
(the `{base}/api/ClientScopes` endpoint — present in every environment, but only AES returns an
`a365:workspace:{id}` scope; not really part of the OAuth flows in the other categories).
`mockResponse`: the GET response. `expectRequest` (optional): `endpoint` (full URL,
query string included), `method`. Then either `expectResult` (the returned scope array)
or `expectErrorContains` — a lookup that fails **must** throw rather than degrade to `[]`,
which is itself a meaningful answer ("this client has no scopes").

## Coverage checklist

- [x] Authorize URL — Commercial + Gov + AES host, `secure` never on `/authorize`, PKCE `S256`
- [x] Authorize URL — `selectWorkspace` strict/optional/none (SPEC §3.1)
- [x] Authorize URL — AES workspace scope requested directly (one trip, no exchange needed, SPEC §5.2/§6)
- [x] Code exchange — public (client_id) vs confidential (Basic); Commercial + AES token hosts
- [x] Workspace exchange — non-Gov (no `secure`) vs Gov (`secure=1`, Commercial→Gov bridge) vs AES (available, no `secure`)
- [x] Refresh — no `scope` sent; Commercial vs Gov (`secure`) vs AES (no `secure`)
- [x] Cross-partition exchange → `access_denied`
- [x] ActionWait — 200/408/410, non-JSON, missing `code`
- [x] Live claims — `iss` / `secure` / `workspaceId` for global, non-Gov, Gov, AES tokens
- [x] ClientScopes — scope array returned, unknown-client empty array, malformed body + non-200 → error (AES host; only AES returns a workspace scope)
- [x] Revocation — request shape + refresh → `invalid_grant` (spec §9; skipped in the TS runner, no `revoke()` in the lib)
- [x] userinfo response shape (`../schemas/userinfo.schema.json`; reference)
- [x] `expires_at` computation (30s skew)
- [x] State-mismatch (CSRF) rejection after ActionWait `200`

## Next

- Wire `../../src/index.test.ts` to load `vectors.json` (proves the vectors match the reference).
- Stand up a shared mock IdP (WireMock/Prism, or recorded interactions) so non-TS SDKs run the same vectors.
