# altium-auth (Java)

[![Maven Central](https://img.shields.io/maven-central/v/com.altium/altium-auth?label=maven-central)](https://central.sonatype.com/artifact/com.altium/altium-auth)
[![CI](https://github.com/AltiumDeveloper/altium-auth/actions/workflows/java-ci.yml/badge.svg)](https://github.com/AltiumDeveloper/altium-auth/actions/workflows/java-ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/AltiumDeveloper/altium-auth/blob/main/libs/java/LICENSE)

Altium 365 OAuth2 / OpenID Connect authentication for Java. Supports both client types across Commercial Cloud, GovCloud, and AES (on-prem):

- **Public clients** (desktop, native) sign in through the browser with PKCE over Altium's **ActionWait** long poll: `AltiumAuthClient.signIn`.
- **Confidential clients** (web/server backends) use the standard **authorization-code redirect** flow: `createAuthorizationUrl` + `exchangeCode`.
- **Workspace tokens**, **refresh**, **revocation**, and first-class **GovCloud** + **AES** support.

**Zero runtime dependencies** (JDK only, on `java.net.http`). Java 17+. Module name `com.altium.auth`.

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

Maven:

```xml
<dependency>
    <groupId>com.altium</groupId>
    <artifactId>altium-auth</artifactId>
    <version>0.2.1</version>
</dependency>
```

Gradle:

```groovy
implementation "com.altium:altium-auth:0.2.1"
```

## Quick start

Build an `AltiumAuthConfig` and construct one `AltiumAuthClient`; instances are thread-safe. Only the client ID and scopes are required, and endpoints default to the Commercial Cloud.

### Public apps (desktop, ActionWait sign-in)

```java
import com.altium.auth.AltiumAuthClient;
import com.altium.auth.AltiumAuthConfig;
import com.altium.auth.TokenSet;

AltiumAuthClient client = new AltiumAuthClient(
        AltiumAuthConfig.builder("your-client-id", "openid profile").build());

// Opens a browser login page and waits for the callback.
TokenSet tokens = client.signIn();

// Persist the tokens yourself: an OS credential store, a keyring, or a file.
TokenSet workspace = client.signIntoWorkspace(tokens.accessToken(), "workspace-id-here");
```

By default `signIn` opens the system browser through `java.awt.Desktop` (falling back to `xdg-open`) and also prints the URL. Pass your own opener (an IDE or host bridge, say) to replace both; the library still owns PKCE, ActionWait polling, state correlation, CSRF validation, and the token exchange:

```java
AltiumAuthConfig config = AltiumAuthConfig.builder("your-client-id", "openid profile")
        .openBrowser(url -> myHost.openExternal(url))
        .build();
```

`signIn` blocks until the user finishes or the timeout (default 180 s) passes. Run it off the UI thread. Interrupting the waiting thread aborts the poll with a `TransportException` and keeps the thread's interrupt flag set.

### Confidential apps (web / server, authorization-code redirect)

```java
AltiumAuthClient client = new AltiumAuthClient(
        AltiumAuthConfig.builder("your-client-id", "openid profile offline_access")
                .clientSecret("your-client-secret") // confidential client → HTTP Basic
                .build());
String redirectUri = "https://my-service.example.com/oauth/callback";

// On your login route: build the URL, store state + verifier in the session, then redirect.
AuthorizationRequest request = client.createAuthorizationUrl(redirectUri, null, null, WorkspaceSelection.NONE);
session.setAttribute("oauthState", request.state());
session.setAttribute("oauthVerifier", request.codeVerifier());
response.sendRedirect(request.url());

// On your callback route: verify state, then exchange the code.
if (!req.getParameter("state").equals(session.getAttribute("oauthState"))) {
    throw new IllegalStateException("state mismatch");
}
TokenSet tokens = client.exchangeCode(req.getParameter("code"), (String) session.getAttribute("oauthVerifier"), redirectUri);
```

### GovCloud

```java
AltiumAuthClient client = new AltiumAuthClient(
        AltiumAuthConfig.builder("your-gov-client-id", "openid profile")
                .endpoints(AltiumEndpoints.GOV_CLOUD)
                .build());
TokenSet tokens = client.signIn(); // secure=1 is added to token requests automatically
```

### AES (on-prem)

```java
AltiumEndpoints endpoints = AltiumEndpoints.aes("https://aes.server.example:9785");
List<String> scopes = AltiumAuthClient.getClientScopes(endpoints.scopeEndpoint(), "your-aes-client-id");
AltiumAuthClient client = new AltiumAuthClient(
        AltiumAuthConfig.builder("your-aes-client-id", String.join(" ", scopes))
                .endpoints(endpoints)
                .build());
TokenSet tokens = client.signIn();
```

AES installations often use a private CA. Pass an `HttpClient` that trusts it rather than disabling certificate checks:

```java
HttpClient http = HttpClient.newBuilder().sslContext(myCompanySslContext).build();
AltiumAuthClient client = new AltiumAuthClient(config, http);
List<String> scopes = AltiumAuthClient.getClientScopes(http, endpoints.scopeEndpoint(), "your-aes-client-id");
```

## Using from async code

Every method blocks. To run one asynchronously, put it on an executor, or on a virtual thread from Java 21:

```java
CompletableFuture<TokenSet> refreshed = CompletableFuture.supplyAsync(() -> client.refreshToken(refreshToken), executor);
```

## API reference

| Method | Description |
| --- | --- |
| `createAuthorizationUrl()` / `createAuthorizationUrl(redirectUri, state, codeVerifier, selectWorkspace)` | Build a PKCE authorization URL (no I/O). Null arguments are defaulted. Returns `AuthorizationRequest(url, state, codeVerifier)`. |
| `exchangeCode(code)` / `exchangeCode(code, codeVerifier, redirectUri)` | Authorization-code grant → `TokenSet`. |
| `signIn()` / `signIn(selectWorkspace)` / `signIn(selectWorkspace, timeout)` | Full ActionWait sign-in → `TokenSet`. |
| `signIntoWorkspace(baseAccessToken, workspaceAuthId)` | RFC 8693 workspace exchange → `TokenSet`. |
| `refreshToken(refreshToken)` | Refresh grant (no scope resent) → `TokenSet`. |
| `revokeRefreshToken(refreshToken)` | RFC 7009 revocation (idempotent). |
| `AltiumAuthClient.getClientScopes([http,] scopeEndpoint, clientId)` | Static; scope introspection → `List<String>`. |

### Types

- `AltiumAuthConfig.builder(clientId, scopes)` with `.clientSecret(..)`, `.endpoints(..)` (default `AltiumEndpoints.COMMERCIAL_CLOUD`), `.secure(..)`, `.openBrowser(..)`, `.requestTimeout(..)` (default 30 s); `isConfidential()`, `useSecure()`.
- `AltiumEndpoints(authorizeEndpoint, tokenEndpoint, actionWaitEndpoint, redirectUri[, scopeEndpoint])`: constants `COMMERCIAL_CLOUD`, `GOV_CLOUD`; factory `aes(origin)`.
- `TokenSet(accessToken, tokenType, expiresIn, expiresAt, refreshToken, idToken, scope)`: `expiresAt` is epoch seconds, computed with a 30 s clock-skew buffer. `toString()` omits the tokens.
- `WorkspaceSelection`: `NONE` / `STRICT` / `OPTIONAL`.

> `accessToken` is a signed JWT. Decode it to read `iss`, `workspaceId`, `secure`, and scopes. See [Access token claims](https://altiumdeveloper.github.io/altium-auth/guides/token-claims/).

## Error handling

Every exception is an unchecked `AltiumAuthException`:

| Class | When |
| --- | --- |
| `ConfigurationException` | Missing client ID/scopes, invalid endpoint URL, or empty required argument. |
| `OAuthException` | Token/revocation/scope endpoint returned a non-success status (carries `getStatus()`, `getError()`, `getErrorDescription()`). |
| `ActionWaitException` | ActionWait timed out, was cancelled (410), failed TLS, or returned an unusable body. |
| `StateMismatchException` | Returned state ≠ wait token (CSRF guard). Subclass of `ActionWaitException`. |
| `TransportException` | Network-level failure, or the calling thread was interrupted. |
| `TlsException` | TLS/certificate failure. Subclass of `TransportException`. |

## Development

```bash
./mvnw verify            # unit, transport, and conformance tests
./mvnw javadoc:javadoc   # javadoc lint
```

### Live E2E sign-in

```bash
./mvnw -q compile
java -cp target/classes tools/SignInTest.java YOUR_CLIENT_ID
java -cp target/classes tools/SignInTest.java --env gov YOUR_GOV_CLIENT_ID
java -cp target/classes tools/SignInTest.java --env aes --aes-origin https://aes.server.example:9785 YOUR_AES_CLIENT_ID
```

## Security

Report vulnerabilities privately; see [SECURITY.md](https://github.com/AltiumDeveloper/altium-auth/blob/main/SECURITY.md).

## License

[MIT](https://github.com/AltiumDeveloper/altium-auth/blob/main/libs/java/LICENSE) © Altium Limited
