# AGENTS.md — working model for this repository

This repo is **spec-first and vector-validated**. Read this before changing anything.

## The one rule

> **Behavior is defined by `spec/`, proven by `spec/conformance/vectors.json`, and
> implemented identically in every `libs/<lang>/`.**

You do not "fix a library." You change the **contract** (spec + vectors), then make
every library conform. The vectors are the source of truth for *behavior*; `SPEC.md`
is the source of truth for *semantics and intent*. If code and spec disagree, one of
them is a bug — stop and reconcile before proceeding.

## Map

```
spec/
  SPEC.md                     Normative semantics — the Altium delta over standard OAuth/OIDC. READ FIRST.
  schemas/*.json              JSON Schemas for wire shapes (token claims, ActionWait, token/userinfo).
  conformance/
    vectors.json              Language-neutral behavior vectors. THE contract every library runs.
    README.md                 Vector format + matchers (<any>, contains:, basic(...), epochWithin:, …).
docs/                         Human-visible conceptual guides (language-neutral). In-repo and kept in
                              lock-step with the spec + code — see "Documentation is part of the contract".
libs/
  typescript/                 @altium-developer/altium-auth (npm). Reference implementation.
    src/  test/conformance/   Unit tests live in src; the conformance runner reads ../../../../spec/…
  dotnet/                     Altium.Auth (nuget). Dependency-free by design.
    tests/Altium.Auth.Tests   xUnit conformance runner over the shared vectors.
  python/                     altium-auth (PyPI). Dependency-free (stdlib only).
    tests/conformance/        pytest conformance runner over the shared vectors.
  java/                       com.altium:altium-auth (Maven Central). Dependency-free (JDK only), Java 17+.
    src/test/.../ConformanceTest.java  JUnit conformance runner over the shared vectors.
.github/workflows/            Per-library, path-filtered CI + tag-prefixed release.
```

## Prime directives

1. **No behavior change without a vector.** If you change what bytes go on the wire
   or how a response is interpreted, add/adjust a vector in `spec/conformance/vectors.json`
   first, and reflect the intent in `SPEC.md`. A behavior with no vector is unowned.
2. **Parity across languages.** A capability in one library must exist in all, or be
   an explicit, tracked gap. The single source of gap-tracking is the **conformance
   matrix** in the root `README.md`. Never silently diverge.
3. **Keep the delta thin.** Most of the flow is standard OAuth2/OIDC (RFC 6749/7636/
   8693/7009, OIDC Core). Only the *Altium delta* is specified: ActionWait long-poll,
   `secure=1` Commercial-vs-Gov (AES follows the Commercial rule), the workspace
   token-exchange profile. Don't re-spec standard behavior; don't hand-roll what the
   delta doesn't require.
4. **Dependencies are a decision, not a reflex.** These are security-sensitive clients
   and intentionally dependency-light. Propose and justify, don't just add.
5. **Never weaken a guardrail silently.** The library implementations are validated.
   Changing one requires the change to be captured by a vector and reviewed; explain
   material decisions in the PR (and the spec, where they affect the contract).
6. **Documentation is part of the contract.** `docs/` and each library's README are
   human-visible surface. A change to the spec or a library's public behavior updates
   them in the *same* change — an out-of-date guide is a defect, not a follow-up.

## Task playbooks

**Change or extend the contract** (new field, new grant, changed request shape):
1. Update `spec/SPEC.md` (the semantics + MUST/SHOULD) and, if a wire shape changes,
   the relevant `spec/schemas/*.json`.
2. Add/adjust vectors in `spec/conformance/vectors.json` (see `spec/conformance/README.md`
   for the format). The vector is the contract — write it first.
3. Implement in **every** `libs/<lang>/`.
4. Run **all** conformance runners (see cheat-sheet). All green, or the PR isn't done.
5. Update the human-visible docs: the relevant `docs/*.md` guide(s), each changed
   library's README + CHANGELOG, and the root `README.md` conformance matrix.
6. If the capability is user-exercisable (a new option, flag, method, or grant),
   surface it in **each library's live E2E harness** so it can be tried against a real
   environment — TS `libs/typescript/scripts/test-signin.ts`, .NET
   `libs/dotnet/tools/SignInTest`, Python `libs/python/tools/signin_test.py`, Java
   `libs/java/tools/SignInTest.java`. **These
   harnesses share ONE CLI contract**: the same flags, option names, accepted values,
   and behavior in every language, so an identical command works against any
   implementation (`--env`, `--workspace-env`, `--aes-origin`, `--secure`/`--no-secure`,
   `--scopes`, `--workspace`, `--select-workspace`, `--refresh`, `--userinfo`, `--revoke`,
   `--authorize-url`/`--exchange-code`/`--code-verifier`/`--redirect-uri`; secret via
   `A365_CLIENT_SECRET`). Adding or renaming a flag in one means doing it in all. These
   harnesses are **not** unit-tested (they need network + a browser), so they only stay
   correct if updated in lockstep — an unsurfaced capability, a divergent CLI, or a stale
   call after a signature change, is a defect.

**Fix a bug in one library:**
1. If it's a behavior bug, first add a vector that fails against the buggy behavior.
2. Fix the library; make the vector pass. Then confirm the *other* libraries also pass
   it — if they share the bug, fix them too (directive 2).

**Add a new language (`libs/<lang>`):**
1. Idiomatic implementation of `SPEC.md`. Reuse a certified OIDC lib only if it earns
   its keep; otherwise stay dependency-light.
2. A conformance runner that loads `spec/conformance/vectors.json` and asserts
   `expectRequest`/`expectResult`. Use the TS (`libs/typescript/test/conformance`) or
   .NET (`libs/dotnet/tests/Altium.Auth.Tests`) runner as a template — same vectors,
   same matchers.
3. `.github/workflows/<lang>-ci.yml` (path-filtered on `libs/<lang>/**` + `spec/**`)
   and a `<lang>-release.yml`.
4. Add the library + matrix rows to the root `README.md`.

## Validation cheat-sheet (run from repo root)

```bash
# TypeScript
cd libs/typescript && npm ci && npm run lint && npm run typecheck \
  && npm test && npm run test:conformance && npm run build && cd ../..

# .NET (solution-level; the src project builds with analyzers as errors)
dotnet test libs/dotnet/Altium.Auth.sln -c Release

# Python
cd libs/python && uv sync --extra dev && uv run ruff check . \
  && uv run ruff format --check . && uv run mypy && uv run pytest && cd ../..

# Java
cd libs/java && ./mvnw -B verify javadoc:javadoc \
  && javac -Xlint:all -Werror -cp target/classes -d target/tools tools/SignInTest.java && cd ../..
```

Live end-to-end (needs network + a browser — never in CI): each library ships a
sign-in tool with an **identical CLI** — TS `npm run test:e2e`, .NET
`dotnet run --project libs/dotnet/tools/SignInTest`, Python
`uv run python libs/python/tools/signin_test.py`, Java
`java -cp target/classes tools/SignInTest.java` (from `libs/java`). Keep them at feature *and* interface
parity: every new user-facing capability gets the *same* flag/option in **every**
harness (see playbook step 6), so one command works everywhere. CI builds
`tools/SignInTest` so signature drift can't silently break it; the TS harness is
type-checked when you run it via `tsx`.

## Definition of done (agent PR)

- [ ] Behavior changes are captured by a vector in `spec/conformance/vectors.json`.
- [ ] `SPEC.md` (and schemas, if shapes changed) match the implementation.
- [ ] **Every affected library passes its conformance runner** + unit tests + lint/typecheck/build.
- [ ] Cross-language parity kept, or a gap recorded in the root README conformance matrix.
- [ ] Affected `docs/*.md` guides + library READMEs updated; CHANGELOGs updated.
- [ ] Live E2E harnesses (`scripts/test-signin.ts`, `tools/SignInTest`,
      `libs/python/tools/signin_test.py`, `libs/java/tools/SignInTest.java`) expose any new user-facing capability with the
      *same* CLI flags in every language and still build/type-check — kept at parity.
- [ ] No secrets in code, tests, or CLI args (secrets come from env only).

## Documentation is part of the contract

Conceptual guides live in `docs/` **inside this repo**, deliberately next to the spec and
the implementations so they can change in the same commit as behavior and never drift.
They are the human-facing counterpart to the machine-checked vectors:

- `docs/*.md` — the *why* and the end-to-end flows (protocol-level, language-neutral).
- Each library README — the *how* for that ecosystem.
- `spec/SPEC.md` + schemas are normative; docs must not contradict them.

When you change the spec or a library's public behavior, update the affected guide(s) and
README(s) in the same change. Keep guides as clean, standalone Markdown with working
in-tree links — they are intended to be published as a static site (mkdocs → GitHub
Pages), so avoid repo-only constructs that won't render off GitHub.

## Non-negotiable semantics (see SPEC.md for the full text)

- **ActionWait:** start the long-poll **before** opening the browser (avoids a fast-callback race).
- **`secure=1`** is a token-endpoint parameter (never on `/authorize`); derived from a
  Gov token host, overridable via config. AES follows the Commercial rule (no
  `secure=1`). Commercial, Gov, and AES tokens are never mixed across environments.
- **Refresh** sends no `scope` (retains the original grant). **Revocation** targets
  refresh tokens at `/connect/revocation` and is idempotent (RFC 7009).
- **`state`** doubles as the CSRF guard and the ActionWait connection token; verify it.
