# Changelog

## Unreleased

## [0.2.1] — 2026-10-07

- Python 3.15 is now tested in CI and declared in the package classifiers.

- A transport failure during the ActionWait poll now fails fast instead of reconnecting
  until the sign-in timed out, since retrying an unreachable network doesn't help. A TLS
  failure surfaces as the new `TlsError` (a `TransportError` subclass).

- OAuth errors delivered via the ActionWait callback (e.g. `access_denied`) are surfaced
  as the error itself, not a generic "missing data.code" (SPEC §4.3, vector `aw-error-in-data`).

## [0.2.0] — 2026-09-09

Initial release. Implements the Altium 365 auth spec (`spec/SPEC.md`, contract 0.2.0)
at parity with the TypeScript and .NET libraries; passes the shared conformance vectors.

[0.2.1]: https://github.com/AltiumDeveloper/altium-auth/releases/tag/py-v0.2.1
[0.2.0]: https://github.com/AltiumDeveloper/altium-auth/releases/tag/py-v0.2.0
