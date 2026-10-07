# altium-auth (Python)

[![PyPI](https://img.shields.io/pypi/v/altium-auth?label=pypi)](https://pypi.org/project/altium-auth/)
[![Python](https://img.shields.io/pypi/pyversions/altium-auth.svg)](https://pypi.org/project/altium-auth/)
[![CI](https://github.com/AltiumDeveloper/altium-auth/actions/workflows/python-ci.yml/badge.svg)](https://github.com/AltiumDeveloper/altium-auth/actions/workflows/python-ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/AltiumDeveloper/altium-auth/blob/main/libs/python/LICENSE)

Altium 365 OAuth2 / OpenID Connect authentication for Python. Supports both client types across Commercial Cloud, GovCloud, and AES (on-prem):

- **Public clients** (desktop, native) — browser sign-in with PKCE over Altium's **ActionWait** long-poll: `AltiumAuthClient.sign_in`.
- **Confidential clients** (web/server backends) — the standard **authorization-code redirect** flow: `create_authorization_url` + `exchange_code`.
- **Workspace tokens**, **refresh**, **revocation**, and first-class **GovCloud** + **AES** support.

**Zero runtime dependencies** (stdlib only). Python 3.10+.

## Documentation

The library implements the protocol described in the language-neutral guides (start here if you're new to Altium Identity):

- [Authentication overview](https://altiumdeveloper.github.io/altium-auth/guides/overview/)
- [Register your application](https://altiumdeveloper.github.io/altium-auth/guides/register-your-application/)
- [Web / server apps](https://altiumdeveloper.github.io/altium-auth/guides/web-and-server-apps/)
- [Desktop apps](https://altiumdeveloper.github.io/altium-auth/guides/desktop-apps/)
- [GovCloud](https://altiumdeveloper.github.io/altium-auth/guides/govcloud/)
- [AES (on-prem)](https://altiumdeveloper.github.io/altium-auth/guides/aes/)
- [Access token claims](https://altiumdeveloper.github.io/altium-auth/guides/token-claims/)

## Installation

```bash
pip install altium-auth
```

## Quick start

Construct an `AltiumAuthClient` once with an `AltiumAuthConfig`. Only `client_id` and `scopes` are required — endpoints default to the Commercial Cloud.

### Public apps (desktop — ActionWait sign-in)

```python
from altium_auth import AltiumAuthClient, AltiumAuthConfig

client = AltiumAuthClient(AltiumAuthConfig(client_id="your-client-id", scopes="openid profile"))

# Opens a browser login page and waits for the callback.
tokens = client.sign_in()

# Persist `tokens` yourself — a keyring, an OS credential store, or a file.
workspace = client.sign_into_workspace(tokens.access_token, "workspace-id-here")
```

Provide a custom browser opener (e.g. an IDE/host bridge) via config; the library still owns PKCE, ActionWait polling, state correlation, CSRF validation, and the token exchange:

```python
config = AltiumAuthConfig(
    client_id="your-client-id",
    scopes="openid profile",
    open_browser=lambda url: my_host.open_external(url),
)
```

### Confidential apps (web / server — authorization-code redirect)

```python
from altium_auth import AltiumAuthClient, AltiumAuthConfig

client = AltiumAuthClient(
    AltiumAuthConfig(
        client_id="your-client-id",
        client_secret="your-client-secret",  # confidential client → HTTP Basic
        scopes="openid profile offline_access",
    )
)
redirect_uri = "https://my-service.example.com/oauth/callback"

# On your login route: build the URL, stash state + verifier, then redirect.
req = client.create_authorization_url(redirect_uri=redirect_uri)
session["oauth"] = {"state": req.state, "code_verifier": req.code_verifier}
# redirect(req.url)

# On your callback route: verify state, then exchange the code.
if request.args["state"] != session["oauth"]["state"]:
    raise ValueError("state mismatch")
tokens = client.exchange_code(
    request.args["code"],
    code_verifier=session["oauth"]["code_verifier"],
    redirect_uri=redirect_uri,
)
```

### GovCloud

```python
from altium_auth import AltiumAuthClient, AltiumAuthConfig, GOV_CLOUD_ENDPOINTS

client = AltiumAuthClient(
    AltiumAuthConfig(
        client_id="your-gov-client-id",
        scopes="openid profile",
        endpoints=GOV_CLOUD_ENDPOINTS,
    )
)
tokens = client.sign_in()  # secure=1 is added to token requests automatically
```

### AES (on-prem)

```python
from altium_auth import AltiumAuthClient, AltiumAuthConfig, aes_endpoints

endpoints = aes_endpoints("https://aes.server.example:9785")
scopes = AltiumAuthClient.get_client_scopes(endpoints.scope_endpoint, "your-aes-client-id")
client = AltiumAuthClient(
    AltiumAuthConfig(
        client_id="your-aes-client-id",
        scopes=" ".join(scopes),
        endpoints=endpoints,
    )
)
tokens = client.sign_in()
```

## Using from async code

The library is synchronous. From an event loop, bridge with the stdlib:

```python
import asyncio

tokens = await asyncio.to_thread(client.refresh_token, refresh_token)
```

## API reference

| Method | Description |
| --- | --- |
| `create_authorization_url(*, redirect_uri=None, state=None, code_verifier=None, scopes=None, select_workspace=WorkspaceSelection.NONE)` | Build a PKCE authorization URL (no I/O). Returns `AuthorizationRequest(url, state, code_verifier)`. |
| `exchange_code(code, *, code_verifier=None, redirect_uri=None, timeout=30.0)` | Authorization-code grant → `TokenSet`. |
| `sign_in(*, select_workspace=WorkspaceSelection.NONE, timeout=180.0)` | Full ActionWait sign-in → `TokenSet`. |
| `sign_into_workspace(base_access_token, workspace_auth_id, *, timeout=30.0)` | RFC 8693 workspace exchange → `TokenSet`. |
| `refresh_token(refresh_token, *, timeout=30.0)` | Refresh grant (no scope resent) → `TokenSet`. |
| `revoke_refresh_token(refresh_token, *, timeout=30.0)` | RFC 7009 revocation (idempotent). |
| `AltiumAuthClient.get_client_scopes(scope_endpoint, client_id, *, timeout=30.0)` | Static; scope introspection → `list[str]`. |

### Types

- `AltiumAuthConfig(client_id, scopes, client_secret=None, endpoints=COMMERCIAL_CLOUD_ENDPOINTS, secure=None, open_browser=None)` — properties `is_confidential`, `use_secure`.
- `AltiumEndpoints(authorize_endpoint, token_endpoint, action_wait_endpoint, redirect_uri, scope_endpoint=None)` — constants `COMMERCIAL_CLOUD_ENDPOINTS`, `GOV_CLOUD_ENDPOINTS`; factory `aes_endpoints(origin)`.
- `TokenSet(access_token, token_type, expires_in, expires_at, refresh_token, id_token, scope)` — `expires_at` computed with a 30 s clock-skew buffer.
- `WorkspaceSelection` — `NONE` / `STRICT` / `OPTIONAL`.

> `access_token` is a signed JWT — decode it to read `iss`, `workspaceId`, `secure`, and scopes. See [Access token claims](https://altiumdeveloper.github.io/altium-auth/guides/token-claims/).

## Error handling

All errors subclass `AltiumAuthError`:

| Class | When |
| --- | --- |
| `ConfigurationError` | Missing `client_id`/`scopes`, invalid endpoint URL, or empty required argument. |
| `OAuthError` | Token/revocation/scope endpoint returned a non-success status (carries `.status`, `.error`, `.error_description`). |
| `ActionWaitError` | ActionWait timed out, was cancelled (410), or returned an unusable body. |
| `StateMismatchError` | Returned state ≠ wait token (CSRF guard). Subclass of `ActionWaitError`. |
| `TransportError` | Network-level failure. |
| `TlsError` | TLS/certificate failure. Subclass of `TransportError`. |

## Development

```bash
uv sync --extra dev
uv run pytest            # unit + conformance
uv run ruff check .
uv run mypy
uv build
```

### Live E2E sign-in

```bash
uv run python tools/signin_test.py YOUR_CLIENT_ID
uv run python tools/signin_test.py --env gov YOUR_GOV_CLIENT_ID
uv run python tools/signin_test.py --env aes --aes-origin https://aes.server.example:9785 YOUR_AES_CLIENT_ID
```

## Security

Report vulnerabilities privately — see [SECURITY.md](https://github.com/AltiumDeveloper/altium-auth/blob/main/SECURITY.md).

## License

[MIT](https://github.com/AltiumDeveloper/altium-auth/blob/main/libs/python/LICENSE) © Altium Limited
