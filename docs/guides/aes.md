# AES (on-prem) considerations

Altium Enterprise Server (AES) is a customer-hosted, on-prem installation. The
authentication flows are the same as the [web](./web-and-server-apps.md) and
[desktop](./desktop-apps.md) guides, with the differences
outlined below.

## Its own environment, on a customer domain

Unlike Commercial Cloud (`auth.altium.com`) and GovCloud
(`auth.365-gov.altium.com`), which are fixed Altium-hosted domains, an AES
installation runs on a **customer-controlled origin** — there is no fixed
hostname. Given the AES server's origin (e.g.
`https://aes.server.example:9785`), the base URL is that origin plus
`/unifiedlogin`:

| Purpose                 | URL                                       |
| ----------------------- | ----------------------------------------- |
| Authorize               | `{origin}/unifiedlogin/connect/authorize` |
| Token                   | `{origin}/unifiedlogin/connect/token`     |
| ActionWait poll         | `{origin}/actionwait/await`               |
| `AuthComplete` callback | `{origin}/unifiedlogin/api/AuthComplete`  |
| Scope Introspection     | `{origin}/unifiedlogin/api/ClientScopes`  |

**AES hosts its own ActionWait and callback** — unlike Gov, which has no
ActionWait/callback of its own and shares Commercial's. Every endpoint for an
AES installation lives on the same customer origin.

Because the origin varies per installation, the libraries expose a builder
instead of a fixed constant:

```ts
import { createAesEndpoints } from "@altium-developer/altium-auth";
const endpoints = createAesEndpoints("https://aes.server.example:9785");
```

```csharp
using Altium.Auth;
var endpoints = AltiumEndpoints.Aes("https://aes.server.example:9785");
```

```python
from altium_auth import aes_endpoints
endpoints = aes_endpoints("https://aes.server.example:9785")
```

```java
import com.altium.auth.AltiumEndpoints;
AltiumEndpoints endpoints = AltiumEndpoints.aes("https://aes.server.example:9785");
```

## Single workspace

AES hosts a single workspace, so its ID is known up front and there is nothing
to choose: the **sign-in request should include the scope
`a365:workspace:{workspaceId}`** and the issued access token is already
workspace-scoped — one trip, no token exchange. If the workspace ID is not
already known, the client application can introspect the exact value of that
scope by making a GET request to
`{origin}/unifiedlogin/api/ClientScopes?clientId={clientId}` on the AES
installation.

That endpoint is not AES-specific — Commercial and GovCloud expose it too, at
`{base}/api/ClientScopes` — but only on AES does it return an
`a365:workspace:{workspaceId}` scope. A Cloud client may reach many workspaces,
and none of them follow from its client ID, so on Cloud the response carries
only the client's static scopes and you discover workspaces with
`desWorkspaceInfos` instead.

The [workspace token exchange](./web-and-server-apps.md) is technically
available on AES (it behaves as on Commercial Cloud, without `secure=1`), but it
buys nothing here — it exists for the Cloud case where the user picks a
workspace after signing in. There is no `selectWorkspace` prompt on AES either:
with one workspace, requesting its scope at sign-in is logging into the
workspace.

AES is its own environment. A token issued by an AES installation is only
accepted by that same AES installation — it cannot be exchanged for a Commercial
or GovCloud workspace token, and a Commercial/Gov token cannot be exchanged at
an AES endpoint. There is no equivalent of the Commercial→Gov workspace-bridging
flow for AES.

## Miscellaneous

AES follows the **same rule as Commercial Cloud**: token requests never carry
`secure=1`, and AES-issued tokens carry no `secure` claim.

There is no `workspaceId` claim on the workspace token, and no `selectWorkspace` prompt for AES.

## Related

- [Authentication overview](./overview.md) · [Access token
  claims](./token-claims.md)
- [Web and server application flow](./web-and-server-apps.md) · [Desktop
  application flow](./desktop-apps.md)
