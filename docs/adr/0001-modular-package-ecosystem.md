# ADR-0001: Ship one package with eleven products, not a federation of packages

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** founding maintainer
- **Security impact:** Moderate — version atomicity is a security property

## Context

BlurSecurity must be modular (developers import only what they need — a watch app wanting `BlurKeychain` must not pay for OAuth) but also coherent (types like `SecureBytes`, `ProtectionPolicy`, and `SecurityError` flow through every module). Two physical layouts can deliver modularity: one repository with one `Package.swift` exposing many library products, or many repositories each hosting an independently versioned package (the "federation" model used by some large ecosystems).

A security framework adds a constraint ordinary libraries don't have: **when a vulnerability is fixed in a foundational module, every dependent module must pick up the fix immediately and provably.** In a federation, `BlurOAuth 1.3.2` might pin `BlurSecurityCore ~> 1.1` while the fix lands in Core 1.2, leaving diamond-dependency windows where an app resolves a vulnerable graph that "satisfies" all constraints.

## Decision

One repository, one `Package.swift`, one version number, eleven library products (plus the umbrella). SPM products provide à-la-carte importing; the single semantic version guarantees that any BlurSecurity release is a single, fully tested, internally consistent snapshot of the whole ecosystem. Apps that import only `BlurKeychain` link only `BlurKeychain` and `BlurSecurityCore` — SPM's dead-target elimination means unused products cost nothing at runtime.

## Alternatives Considered

- **Package per module, independent versions.** Maximum decoupling, but creates cross-version compatibility matrices we would have to test (11 modules × supported versions), permits vulnerable-graph resolution as described above, and multiplies release engineering. Rejected: the flexibility exclusively benefits us as maintainers, while the risk lands on users.
- **Monolithic single target.** Simplest, but forces every app to compile and link the full surface, violates the composability pillar, and blurs internal boundaries (nothing stops `Keychain` code from reaching into `OAuth`). Rejected.
- **Umbrella-only public API with internal targets.** Hides modularity from users entirely. Rejected: watch apps and extensions have real binary-size and review-surface reasons to import narrowly.

## Consequences

- Easier: atomic security releases; one CHANGELOG; cross-module refactors land in one PR; integration tests always test shipped combinations.
- Harder: a breaking change in any one module forces a major version for the whole ecosystem. Accepted deliberately — it pressures us toward additive evolution, which is what API stability demands anyway.
- Security: no diamond-dependency vulnerability windows; an app's `Package.resolved` names exactly one BlurSecurity version, making audits trivial.

## Revisit When

A module's release cadence diverges radically from the rest (e.g. an experimental module iterating weekly against a stable core), or SPM gains first-class support for versioned sub-packages within one repository.
