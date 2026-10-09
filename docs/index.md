# Altium 365 Auth

Client libraries for **Altium 365 authentication** — OAuth2/OpenID Connect with PKCE,
the Altium **ActionWait** desktop sign-in flow, workspace token-exchange,
refresh/revocation, **GovCloud**, and **AES** (on-prem) deployments — built to a
single language-neutral specification and held to one shared conformance suite.

The spec is the source of truth; each library is a hand-written, idiomatic
implementation that is *validated by the same vectors*. Change the contract once, and
every library's CI proves it still conforms.

## Get started

Pick the flow that matches your application:

- **Desktop** (can't host a redirect) → [Desktop apps](guides/desktop-apps.md)
  — browser sign-in with PKCE over ActionWait.
- **Web / server backends** (host a redirect) → [Web & server apps](guides/web-and-server-apps.md)
  — the standard authorization-code redirect flow.

New to Altium Identity? Start with the [Overview](guides/overview.md), then
[Register your application](guides/register-your-application.md).

## Libraries

Full API reference and examples for each library are on this site (the **Libraries** tab):

| Library | Docs |
| --- | --- |
| `@altium-developer/altium-auth` | [TypeScript](libraries/typescript.md) |
| `Altium.Auth` | [.NET](libraries/dotnet.md) |
| `altium-auth` | [Python](libraries/python.md) |
| `com.altium:altium-auth` | [Java](libraries/java.md) |

All are in **preview** — the API may change as the spec and libraries evolve.

## How it stays in sync

The [conformance vectors](specification/conformance.md) are the enforcement layer: every library
runs the **same** `spec/conformance/vectors.json` and asserts the same requests and
outcomes, so the implementations can't drift. The normative behavior lives in the
[integration spec](specification/spec.md).

## Topics

- [GovCloud](guides/govcloud.md) — Commercial vs Gov and the `secure=1` two-token model
- [AES (on-prem)](guides/aes.md) — customer-hosted installations of Altium Enterprise Server
- [Access token claims](guides/token-claims.md) — what's inside a token (`iss`, `workspaceId`, `secure`, scopes)
