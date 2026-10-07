# altium-auth

Client libraries for **Altium 365 authentication** (OAuth2/OIDC + PKCE, workspace
token-exchange, refresh/revocation, and the Altium **ActionWait** desktop flow),
built to a single **language-neutral specification** and held to one shared
**conformance suite**.

The spec is the source of truth; each library is a hand-written, idiomatic
implementation that is *validated by the same vectors*. Change the contract once,
and every library's CI proves it still conforms.

## Layout

```
spec/                     Normative spec + JSON Schemas + conformance vectors (the source of truth)
  SPEC.md                 The Altium delta over standard OAuth/OIDC
  schemas/                JSON Schemas (token claims, ActionWait, token response, userinfo)
  conformance/
    vectors.json          Language-neutral test vectors — every library runs these
    README.md             Vector format + matchers
docs/                     Conceptual auth guides (language-neutral)
libs/
  typescript/             @altium-developer/altium-auth
  dotnet/                 Altium.Auth
  python/                 altium-auth (PyPI)
.github/workflows/        Per-library CI + release (path-filtered)
```

`spec/` and `docs/` are shared and language-neutral. Everything a given ecosystem
needs to build/test/publish lives under that library's `libs/<lang>/` directory.

## Libraries

| Library | Package | Version | Status |
| --- | --- | --- | --- |
| [`libs/typescript`](libs/typescript) | [`@altium-developer/altium-auth`](https://www.npmjs.com/package/@altium-developer/altium-auth) | [![npm](https://img.shields.io/npm/v/@altium-developer/altium-auth?label=npm)](https://www.npmjs.com/package/@altium-developer/altium-auth) | 🧪 preview |
| [`libs/dotnet`](libs/dotnet) | [`Altium.Auth`](https://www.nuget.org/packages/Altium.Auth) | [![nuget](https://img.shields.io/nuget/v/Altium.Auth?label=nuget)](https://www.nuget.org/packages/Altium.Auth) | 🧪 preview |
| [`libs/python`](libs/python) | [`altium-auth`](https://pypi.org/project/altium-auth/) | [![pypi](https://img.shields.io/pypi/v/altium-auth?label=pypi)](https://pypi.org/project/altium-auth/) | 🧪 preview |

## Documentation

The conceptual guides in [`docs/`](docs/) and the specification are published as a
[Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) site at
**<https://altiumdeveloper.github.io/altium-auth/>**. The site is built **from source in
CI** (`.github/workflows/docs.yml`) — nothing generated is committed. Preview locally:

```bash
pip install -r requirements-docs.txt
mkdocs serve
```

## How the libraries stay in sync

The conformance vectors are the enforcement layer:

1. **One contract.** `spec/conformance/vectors.json` defines the expected request
   shapes and outcomes (authorize URL, token requests, ActionWait, revocation, …).
2. **Every library runs them.** Each `libs/<lang>` has a conformance runner that
   reads the *same* `vectors.json` and asserts the same expectations:
   - TypeScript: `npm run test:conformance` (in `libs/typescript`)
   - .NET: `dotnet test libs/dotnet/tests/Altium.Auth.Tests`
3. **CI gates on it.** A change under `spec/**` triggers **every** library's CI
   (path filter), so a contract change that desyncs any implementation fails in
   the same PR. A change under `libs/<lang>/**` triggers only that library.
4. **Atomic contract commits.** Spec + vector + all affected libraries change in
   one reviewed PR.

## Conformance matrix

Which shared vectors each library executes. `live` = behavioral reference that
needs a real server (skipped by offline runners in both).

| Vector group | TypeScript | .NET | Python |
| --- | --- | --- | --- |
| authorizeUrl | ✅ | ✅ | ✅ |
| tokenRequest (exchange/workspace/refresh, Gov `secure=1`, AES host, cross-partition) | ✅ | ✅ | ✅ |
| actionWait (200/408/410/non-JSON/missing-code/CSRF) | ✅ | ✅ | ✅ |
| clientScopes (scope introspection) | ✅ | ✅ | ✅ |
| revocation — `revoke-refresh-token` | ✅ | ✅ | ✅ |
| revocation — `revoke-then-refresh-invalid-grant` | live | live | live |
| userinfo (response shape) | schema ref | schema ref | schema ref |
| liveClaims (decoded token claims) | live | live | live |

## Versioning & releases

- **Spec** is versioned (`spec/conformance/vectors.json` → `version`). Each library
  declares which contract it targets; the spec CHANGELOG is the contract-change log.
- **Libraries version independently** and publish from tag-prefixed releases:
  - `ts-v*` → npm (`.github/workflows/typescript-release.yml`)
  - `dotnet-v*` → nuget.org (`.github/workflows/dotnet-release.yml`)
  - `py-v*` → PyPI (`.github/workflows/python-release.yml`)
- Package `repository.directory` metadata points consumers at the right subdirectory.

## Adding a new language

1. `libs/<lang>/` with an idiomatic implementation of the spec.
2. A conformance runner that reads `spec/conformance/vectors.json` and asserts
   `expectRequest`/`expectResult` (see the TS/.NET runners as references).
3. `.github/workflows/<lang>-ci.yml` (path-filtered on `libs/<lang>/**` + `spec/**`)
   and a `<lang>-release.yml`.
4. Add rows to the tables above.

## License

MIT — see [LICENSE](LICENSE).
