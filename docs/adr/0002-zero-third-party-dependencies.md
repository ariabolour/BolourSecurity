# ADR-0002: Zero third-party dependencies, permanently

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** founding maintainer
- **Security impact:** High — this is a supply-chain control

## Context

Swift packages routinely pull in dependency graphs the author has never audited. For most libraries that is a pragmatic trade. For a security framework it is a contradiction: BolourSecurity asks apps in banking, healthcare, and government to place it inside their trust boundary. Every transitive dependency we add is a vendor those apps did not choose, with its own maintainers, release process, and compromise surface. Supply-chain attacks on package ecosystems are no longer hypothetical; they are the dominant modern vector.

There are real temptations: swift-crypto for algorithm breadth, swift-certificates for X.509, a testing helper here, a lint plugin there.

## Decision

BolourSecurity's package graph contains **zero third-party dependencies — permanently, including test targets, benchmark targets, and build/lint plugins.** We depend on the Swift standard library and Apple's SDK frameworks (Foundation, CryptoKit, Security, LocalAuthentication, DeviceCheck, AuthenticationServices, os). Where an Apple SDK lacks a capability (e.g. full X.509 parsing), we implement the minimal slice we need in-tree (`BolourCertificates` parses exactly the fields required for validation and pinning) or we declare the capability out of scope — we do not import it.

Development *tooling invoked from CI* (formatters, DocC) may run as external processes, but nothing third-party is ever linked into, or resolvable from, `Package.swift`.

## Alternatives Considered

- **Allow apple/swift-crypto and apple/swift-certificates ("it's still Apple").** Closest call. These are high-quality, Apple-stewarded, and open. Rejected for now: they still add resolvable graph nodes, their versioning is independent of OS SDKs, and our platform floor gives us CryptoKit natively — swift-crypto exists primarily for Linux, which we do not target. Revisit condition below.
- **Allow dev-dependencies only.** Test-target dependencies still appear in `Package.resolved` and still execute code on contributor and CI machines. Rejected; Swift Testing ships with the toolchain and suffices.
- **Vendoring (copying source in-tree).** Vendored code is a hidden dependency with worse update hygiene. Rejected except for the case where we *author* a minimal implementation ourselves, with our own tests and review.

## Consequences

- Easier: app security teams audit exactly one vendor; `Package.resolved` is one line; no dependency CVEs, ever, by construction.
- Harder: we implement some things ourselves (minimal DER/X.509 parsing, JOSE serialization) — accepted, scoped narrowly, and covered by fuzzing (see TestingStrategy).
- Security: our compromise surface equals our repository plus Apple's SDKs. Nothing else.

## Revisit When

We decide to support server-side Swift (Linux would require swift-crypto), or Apple begins shipping swift-certificates *in the OS SDK*.
