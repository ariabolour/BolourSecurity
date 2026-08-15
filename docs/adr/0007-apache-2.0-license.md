# ADR-0007: License the project under Apache License 2.0

- **Status:** Accepted
- **Date:** 2026-08-15
- **Deciders:** founding maintainer
- **Security impact:** Low — governs redistribution and patent terms, not runtime behavior

## Context

ROADMAP.md recorded the intent from the project's earliest planning ("license finalized... before tagging") without formally closing the decision: Apache-2.0, on the stated reasoning that a patent grant matters to the project's enterprise audience. This module ships security-critical code — certificate pinning, key custody, token handling — into applications that make their own compliance and redistribution decisions; the license terms are load-bearing for adoption, not a formality to defer indefinitely. This ADR closes that open decision before the v1.0 tag.

## Decision

**BolourSecurity is licensed under the Apache License, Version 2.0.** The `LICENSE` file at the repository root carries the full text; every module inherits it from the single root license (no per-module licensing).

## Alternatives Considered

- **MIT.** Simpler and equally permissive for use/modification/redistribution, but carries no explicit patent grant or termination-on-litigation clause. For a library whose entire purpose is closing off security vulnerability classes, leaving patent terms silent is a gap enterprise legal review would flag — exactly the audience ROADMAP.md named. Rejected.
- **BSD-3-Clause.** Same patent-silence gap as MIT, plus a non-endorsement clause with no meaningful benefit here over Apache-2.0's own trademark section (§6). Rejected.
- **Dual-license / source-available.** Would fund maintenance more directly but directly contradicts VISION.md and MANIFESTO.md's framing of BolourSecurity as open infrastructure adopted for its security properties, not a commercial product — the trust model depends on the code being freely auditable and forkable. Rejected without a stronger reason to reopen it.

## Consequences

- Easier: enterprise adopters get an explicit patent license and litigation-termination clause without a legal escalation to ask for one; contributors' patent contributions are covered by the same grant they receive.
- Harder: Apache-2.0's attribution/NOTICE requirements are slightly heavier for downstream redistributors than MIT's — acceptable given the audience this is written for.
- Migration: none — this is the first license the project ships under; there is no prior license to reconcile.
- **Security consequences:** none identified. The license governs redistribution and patent terms; it grants no one early access to vulnerabilities and changes no runtime guarantee this package makes.

## Revisit When

Only if a future contribution or dependency (still bound by [ADR-0002](0002-zero-third-party-dependencies.md)'s zero-third-party-dependency rule, so this should stay rare) carries license terms incompatible with Apache-2.0 — at which point the incompatibility, not this decision, is what gets revisited first.
