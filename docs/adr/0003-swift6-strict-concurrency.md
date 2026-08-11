# ADR-0003: Swift 6 language mode with complete strict concurrency

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** founding maintainer
- **Security impact:** Moderate — data races on security state are vulnerabilities

## Context

BlurSecurity launches in the Swift 6 era. Security code is exactly where data races do the most damage: a torn read of an authentication flag, a key cache mutated from two tasks, a token refresh raced by concurrent requests producing two live refresh tokens (and, with rotation-detecting servers, a forced logout or session hijack window). We can adopt Swift 6 language mode with `StrictConcurrency=complete` from day one, or start in Swift 5 mode and migrate.

Greenfield status makes this decision cheap now and expensive later.

## Decision

The package declares `swiftLanguageModes: [.v6]` with complete strict concurrency checking, from the first commit, in every target including tests and benchmarks. Consequences for API design:

- Every public type is `Sendable` unless there is a documented reason it cannot be; non-`Sendable` public types are design smells requiring justification in review.
- Mutable state is confined to the three actors named in [Architecture.md §6](../Architecture.md) (`TokenManager`, `Vault`, `AttestationService`). Everything else is value types.
- `@unchecked Sendable` is forbidden in public API and requires an ADR-level justification comment plus two-maintainer review anywhere internal (expected uses: wrapping `SecKey`/`LAContext`, whose thread-safety Apple documents but the compiler cannot see).
- No public API accepts or returns non-`Sendable` closures across isolation boundaries.
- `@MainActor` appears only where the OS requires main-thread interaction (presentation anchors), always in the signature.

## Alternatives Considered

- **Swift 5 mode with warnings-as-errors on concurrency.** Softer landing for contributors, but grandfathers ambiguity into the public API (implicit `@preconcurrency`, un-audited `Sendable`). Migration later would be a breaking change over a mature API. Rejected: greenfield is the one moment strictness is free.
- **Minimal checking, actor-per-module.** Over-serializes inherently value-semantic operations (hashing behind an actor is absurd) and hides design errors instead of surfacing them. Rejected.

## Consequences

- Easier: whole classes of security-relevant races are compile-time errors; the concurrency contract of every API is visible in its signature; adopting apps in Swift 6 mode get zero warnings from us.
- Harder: contributor bar is higher; some Apple APIs need careful isolation wrappers (`LAContext`, delegate-based `URLSession` callbacks); occasional friction with not-yet-annotated SDK corners.
- Security: token refresh, keychain caching, and attestation state are provably race-free at the type level.

## Revisit When

Never expected to weaken. Revisit only to *tighten* (e.g. adopting new isolation features such as isolated conformances) as Swift evolves.
