# AGENTS.md

Package: `@ankhorage/auth-github`

A standalone GitHub App OAuth user-authentication adapter for the released `@ankhorage/auth` AuthPort.
The auth adapter owns identity, user token exchange, and server-side session/attempt boundaries;
`@ankhorage/repository` owns repository discovery, API rate limits, and materialization.

## Required repository instructions

Before editing, read this file and inspect `.agents/skills/`. Load:
- `.agents/skills/ankhorage-coding-rules/SKILL.md`
- `.agents/skills/ankhorage-project-structure/SKILL.md`
- `.agents/skills/hexagonal-architecture/SKILL.md` for feature and adapter changes.

Use published public APIs only; no sibling source imports or unpublished dependencies.
Keep the package standalone, provider-specific credentials server-only, and package functions documented
with Paradox comments. Never log, persist in plaintext, or put GitHub tokens in URLs, browser bundles,
diagnostics, snapshots or generated documentation. The host provides durable, per-session storage and
atomically consumed authorization attempts. Do not add in-memory production fallbacks.

## Delivery

Prefer task branches and pull requests, conventional commits, Changesets and exact-head CI.
Only an explicit owner instruction permits a bootstrap update on `main`.
Run build, typecheck, lint, Knip, tests and format checks, and validate packed consumers before release.
Do not regenerate release-owned README/Paradox outputs during ordinary development.
