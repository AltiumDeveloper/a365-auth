# Changelog

All notable changes to this package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.2.1] — 2026-10-07

- **The ActionWait poll now reconnects when `HttpClient`'s request timeout fires.** The
  100-second default is shorter than the service's hold interval, so a sign-in that took
  longer than that used to fail. Any other transport failure, TLS included, still fails
  fast: retrying an unreachable network doesn't help.

- **Multi-targeting: `netstandard2.0`, `net8.0`, `net10.0`.** `netstandard2.0` makes the
  package installable in .NET Framework 4.6.1+ projects (4.8 included), which previously
  could not reference it at all — the package shipped `lib/net8.0/` only.

- **JSON now uses the BCL's `DataContractJsonSerializer`** instead of `System.Text.Json`,
  keeping the package dependency-free on *every* target. `System.Text.Json` is in-box on
  `net8.0`/`net10.0` but a package on `netstandard2.0`, and on .NET Framework it arrives
  with transitive assemblies and binding redirects. Wire behavior is unchanged and pinned
  by the shared conformance vectors, which now also run on `net48` against the
  `netstandard2.0` asset.

  Two consequences for consumers:
  - `TokenSet` is annotated with `[DataContract]`/`[DataMember]` rather than
    `[JsonPropertyName]`. Code that serializes a `TokenSet` itself (for example caching one
    to disk with `System.Text.Json`) now gets .NET property names instead of the OAuth
    snake_case names, unless it maps them explicitly.
  - An ActionWait 200 whose `data.code` is present but not a string is reported as an
    unparseable body rather than a missing `data.code`. No vector covers that case.

- **Surface OAuth errors delivered via the ActionWait callback** — a `200` whose `data`
  carries an `error` (e.g. `access_denied`, including a cross-partition workspace scope
  requested at sign-in) now fails with that error instead of a generic "missing
  data.code". Mirrors SPEC §4.3 and the `aw-error-in-data` conformance vector.

## [0.2.0] — 2026-09-04

Initial release. Implements the Altium 365 auth spec (`spec/SPEC.md`, contract 0.2.0) at
parity with the TypeScript library; passes the shared conformance vectors.

[0.2.1]: https://github.com/AltiumDeveloper/altium-auth/releases/tag/dotnet-v0.2.1
[0.2.0]: https://github.com/AltiumDeveloper/altium-auth/releases/tag/dotnet-v0.2.0
