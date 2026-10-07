# Changelog

## Unreleased

- A TLS failure during the ActionWait poll now fails fast instead of reconnecting, and
  surfaces as the new `TlsError` (a `TransportError` subclass).

## 0.2.0

Initial release. Implements the Altium 365 auth spec (`spec/SPEC.md`, contract 0.2.0)
at parity with the TypeScript and .NET libraries; passes the shared conformance vectors.

- OAuth errors delivered via the ActionWait callback (e.g. `access_denied`) are surfaced
  as the error itself, not a generic "missing data.code" (SPEC §4.3, vector `aw-error-in-data`).
