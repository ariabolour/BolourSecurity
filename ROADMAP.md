# Roadmap

> **Where things actually stand:** all code described through v1.0 below has shipped — see [CHANGELOG.md](CHANGELOG.md) for what's implemented and the limitations it names explicitly. Some v0.1/v0.5-era *process* acceptance criteria below (CI matrix breadth, DocC coverage audits, the 90%-coverage gate, benchmark suites, example apps, a device-farm lane) are still partial or outstanding rather than met milestone-by-milestone in order — the modules landed faster than the tooling around them. Treat the criteria below as the standing bar for v2.0 and beyond, not a claim that every earlier box is checked.
>
> **Why the current tag is `0.9.0-beta`, not `1.0.0`:** every module this ladder scopes through v1.0 already exists in code. The reason the package isn't tagged 1.0.0 is that this ladder's v1.0 *acceptance criteria* — the stability promise, complete DocC, real-device validation, an audit — are process gates, not module gates, and none of them are met yet. `0.9.0-beta` is the honest read of that: feature-complete against the v1.0 module scope, not yet earning the v1.0 stability promise. See below for exactly what closes that gap.

The path from this blueprint to the security foundation for Apple platforms. Vision, mission, and core values live in [VISION.md](VISION.md); the five-year arc there is the destination, this file is the route. Releases ship when their acceptance criteria are met — readiness over calendar ([MANIFESTO](MANIFESTO.md): never optimize for speed).

Modules land bottom-up because the layers do ([Architecture](docs/Architecture.md)): each release's modules build only on already-shipped, already-hardened layers.

## What's Required Before 1.0.0

Nine gates, tracked honestly rather than aspirationally. This is the standing bar — a change here is a change to this list, not a quiet redefinition of "done."

| Gate | Status | Notes |
|---|---|---|
| Stable, reviewed public API | **Not met** | API review checklist exists ([APIDesignPhilosophy.md](docs/APIDesignPhilosophy.md#the-api-review-checklist)) and has been applied by the implementing maintainer; no independent reviewer has challenged it yet |
| Complete DocC | **Not met** | Landing page only ([CHANGELOG](CHANGELOG.md#known-limitations)); per-module reference site and tutorials outstanding |
| Real-device validation | **Not met** | Test-tier infrastructure exists ([Integration Testing](docs/IntegrationTesting.md)); no device farm or CI lane executes it yet |
| Integration sample app | **Not met** | `BolourSecurityIntegrationApp` and `BolourSecurityDemo` are specified (below) but not built |
| Security review | **Not met** | Internal audit only (this repository's own hardening passes); no independent security engineer has reviewed the codebase |
| CI quality gates | **Partial** | Build matrix, tests, zero-dependency guard, and format lint are live ([pr.yml](.github/workflows/pr.yml)); coverage is informational-only, no doc-build or API-diff gate yet |
| Migration policy | **Partial** | [ReleaseStrategy.md](docs/ReleaseStrategy.md) and the API review checklist exist; no migration guide has ever been exercised (there's been no breaking change to migrate through yet) |
| Semantic versioning rules | **Met (declared, not yet tested)** | [ReleaseStrategy.md](docs/ReleaseStrategy.md) states the policy; it hasn't been exercised across a real breaking change |
| External usage feedback | **Not met** | The package has not yet been published; there are no external adopters |

**Specified, not built — ready for a dedicated follow-up:**
- **`BolourSecurityDemo`** — one polished example app (not ten) demonstrating a realistic integration: Keychain token storage, biometric-gated retrieval, Secure Enclave signing, encrypted file storage (Vault), certificate pinning, OAuth PKCE sign-in, and the App Attest lifecycle, with clear production/demo boundaries. Teaches architecture, not just API syntax.
- **`BolourSecurityIntegrationApp`** — a minimal app-hosted test target whose sole job is running the device-required/entitlement-required test tiers ([Integration Testing](docs/IntegrationTesting.md)) as a real host process with real entitlements, closing the "unentitled `xctest` host" gap that currently skip-gates every hardware-backed round-trip in CI.
- **A device-farm CI lane** — no such infrastructure exists today. Candidates (unevaluated): Xcode Cloud device testing, a self-hosted Mac-mini + iPhone runner pool, or a commercial device-farm service (AWS Device Farm, BrowserStack App Live).

## v0.1 — Foundation *(first public code)*

**Ships:** `Package.swift` + repository scaffolding; **BolourSecurityCore** complete; **BolourKeychain** complete; **BolourCrypto** (hashing, symmetric sealing, randomness, KDFs, software signing keys — Secure Enclave lands in 0.5); CI matrix, docs pipeline, and every quality gate live from the first PR ([CICDStrategy](docs/CICDStrategy.md)); license finalized (intent: Apache-2.0 — patent grant matters to our enterprise audience; decision recorded as an ADR before tagging).

**Acceptance criteria:**
- The five-minute win is real: add package → store a secret → read it back, on all five platforms.
- 100% public-API DocC + *Store Your First Secret* tutorial; CAVP vectors green; descriptor-mapping tests exhaustive; 90% coverage floor enforced.
- All ADR-documented rules mechanically enforced (import-graph lint, empty `Package.resolved` guard, API-diff gate armed for 0.2+).

## v0.5 — Capabilities *(the local-security story complete)*

**Ships:** **BolourCrypto** completed (Secure Enclave keys per [ADR-0006](docs/adr/0006-secure-enclave-first-key-design.md), key agreement); **BolourBiometrics**; **BolourSecureStorage** (Vault + TokenStore); **BolourCertificates**; **BolourNetworkSecurity**; **SecureNotes** example app; benchmark suite + device-farm CI lane; first Security Considerations articles for every shipped module.

**Acceptance criteria:**
- An app can build a biometry-gated encrypted vault with pinned networking using nothing but BolourSecurity — the full Layer 0–3 local stack, composing through Core seams as designed.
- Fuzzing lanes live (DER + envelope parsers) with checked-in corpora; crash-free invariant holds through a full nightly window.
- From 0.5 onward we *behave* as API-stable (breaks still allowed, each one changelog-documented with migration notes) — practicing the 1.0 discipline before it binds ([ReleaseStrategy](docs/ReleaseStrategy.md)).

## v1.0 — The Platform *(the stability promise)*

**Ships:** **BolourJWT**; **BolourAppIntegrity** (+ server-side verification guide with golden fixtures); **BolourOAuth**; **BolourSecurity** umbrella; **SignInDemo** example app; migration guides (raw Security.framework, KeychainAccess, Valet) + the `migrate(from:)` keychain helper; pin-generation tooling; published docs site; launch per [AdoptionStrategy](docs/AdoptionStrategy.md).

**Acceptance criteria:**
- Semantic versioning promise in force: API breakage gate hard-fails; support window active.
- The full attack corpus (JWT confusion, pinning bypass, replay fixtures) green as permanent regression suites; OAuth refresh-storm suites green under TSan.
- Every module: complete DocC with Security Considerations + Common Mistakes; specs' "Prevented:" claims mapped 1:1 to named test suites.
- Benchmarks published in release notes; both example apps built in CI.

## v2.0 — Trust & Depth *(the audited era)*

**Ships:** independent third-party security audit (findings + remediations published — the Year 3 vision milestone); mTLS client identities (BolourCertificates + BolourNetworkSecurity); RS256/PS256 with its confusion-surface ADR (BolourJWT); vault key-escrow/recovery option (BolourSecureStorage, own ADR); DPoP sender-constrained tokens (BolourOAuth + BolourCrypto); LTS-channel decision per [MaintenanceStrategy](docs/MaintenanceStrategy.md); deprecation-to-removal cycle exercised cleanly for any 1.x deprecations.

**Acceptance criteria:** audit published with all Critical/High findings remediated; enterprise-blocking gaps (mTLS, RSA IdPs) closed without weakening a single default; first regulated-industry case studies live.

## v3.0 — Ecosystem *(the platform others build on)*

**Ships:** policy plugin seams (enterprise key-escrow rules, custom attestation backends — the Year 4 vision); server-side reference implementations (App Attest verification, JWT interop) as documented companion code; token-exchange (RFC 8693); post-quantum primitives at parity with CryptoKit's support (adopted the release after Apple ships them); JWE if demand materialized ([BolourJWT roadmap](docs/modules/BolourJWT.md)).

**Acceptance criteria:** at least one shipping third-party integration through the plugin seams; multi-maintainer governance fully real (security-review rotation staffed by 3+); the annual maintenance scorecard ([MaintenanceStrategy §7](docs/MaintenanceStrategy.md)) published twice with all five facts green.

## Beyond — The Five-Year Vision

Standard-status: the assumed baseline for Apple-platform security, same-week OS support as routine, zero known-exploited vulnerabilities in released versions, and multiple organizations sharing stewardship. In full: [VISION.md](VISION.md).

---

*Per-module roadmaps (the "Future Roadmap" section of each [module spec](docs/modules/)) feed this file; conflicts resolve here. Unversioned ideas live in Discussions until they earn a release.*
