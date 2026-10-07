# Changelog

All notable changes to this package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- **A transport failure during the ActionWait poll now reconnects** instead of aborting
  the sign-in. `HttpClient`'s 100-second default timeout is shorter than the service's
  hold interval, so a sign-in that took longer than that used to fail. A TLS failure
  still fails fast, since it is a configuration error.

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

## [0.2.0] — 2026-09-04

Initial release. Implements the Altium 365 auth spec (`spec/SPEC.md`, contract 0.2.0) at
parity with the TypeScript library; passes the shared conformance vectors.
