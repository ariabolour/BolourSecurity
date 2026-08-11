# Roadmap

The path from this blueprint to the security foundation for Apple platforms. Vision, mission, and core values live in [VISION.md](VISION.md); the five-year arc there is the destination, this file is the route. Releases ship when their acceptance criteria are met — readiness over calendar ([MANIFESTO](MANIFESTO.md): never optimize for speed).

Modules land bottom-up because the layers do ([Architecture](docs/Architecture.md)): each release's modules build only on already-shipped, already-hardened layers.

## v0.1 — Foundation *(first public code)*

**Ships:** `Package.swift` + repository scaffolding; **BlurSecurityCore** complete; **BlurKeychain** complete; **BlurCrypto** (hashing, symmetric sealing, randomness, KDFs, software signing keys — Secure Enclave lands in 0.5); CI matrix, docs pipeline, and every quality gate live from the first PR ([CICDStrategy](docs/CICDStrategy.md)); license finalized (intent: Apache-2.0 — patent grant matters to our enterprise audience; decision recorded as an ADR before tagging).

**Acceptance criteria:**
- The five-minute win is real: add package → store a secret → read it back, on all five platforms.
- 100% public-API DocC + *Store Your First Secret* tutorial; CAVP vectors green; descriptor-mapping tests exhaustive; 90% coverage floor enforced.
- All ADR-documented rules mechanically enforced (import-graph lint, empty `Package.resolved` guard, API-diff gate armed for 0.2+).

## v0.5 — Capabilities *(the local-security story complete)*

**Ships:** **BlurCrypto** completed (Secure Enclave keys per [ADR-0006](docs/adr/0006-secure-enclave-first-key-design.md), key agreement); **BlurBiometrics**; **BlurSecureStorage** (Vault + TokenStore); **BlurCertificates**; **BlurNetworkSecurity**; **SecureNotes** example app; benchmark suite + device-farm CI lane; first Security Considerations articles for every shipped module.

**Acceptance criteria:**
- An app can build a biometry-gated encrypted vault with pinned networking using nothing but BlurSecurity — the full Layer 0–3 local stack, composing through Core seams as designed.
- Fuzzing lanes live (DER + envelope parsers) with checked-in corpora; crash-free invariant holds through a full nightly window.
- From 0.5 onward we *behave* as API-stable (breaks still allowed, each one changelog-documented with migration notes) — practicing the 1.0 discipline before it binds ([ReleaseStrategy](docs/ReleaseStrategy.md)).

## v1.0 — The Platform *(the stability promise)*

**Ships:** **BlurJWT**; **BlurAppIntegrity** (+ server-side verification guide with golden fixtures); **BlurOAuth**; **BlurSecurity** umbrella; **SignInDemo** example app; migration guides (raw Security.framework, KeychainAccess, Valet) + the `migrate(from:)` keychain helper; pin-generation tooling; published docs site; launch per [AdoptionStrategy](docs/AdoptionStrategy.md).

**Acceptance criteria:**
- Semantic versioning promise in force: API breakage gate hard-fails; support window active.
- The full attack corpus (JWT confusion, pinning bypass, replay fixtures) green as permanent regression suites; OAuth refresh-storm suites green under TSan.
- Every module: complete DocC with Security Considerations + Common Mistakes; specs' "Prevented:" claims mapped 1:1 to named test suites.
- Benchmarks published in release notes; both example apps built in CI.

## v2.0 — Trust & Depth *(the audited era)*

**Ships:** independent third-party security audit (findings + remediations published — the Year 3 vision milestone); mTLS client identities (BlurCertificates + BlurNetworkSecurity); RS256/PS256 with its confusion-surface ADR (BlurJWT); vault key-escrow/recovery option (BlurSecureStorage, own ADR); DPoP sender-constrained tokens (BlurOAuth + BlurCrypto); LTS-channel decision per [MaintenanceStrategy](docs/MaintenanceStrategy.md); deprecation-to-removal cycle exercised cleanly for any 1.x deprecations.

**Acceptance criteria:** audit published with all Critical/High findings remediated; enterprise-blocking gaps (mTLS, RSA IdPs) closed without weakening a single default; first regulated-industry case studies live.

## v3.0 — Ecosystem *(the platform others build on)*

**Ships:** policy plugin seams (enterprise key-escrow rules, custom attestation backends — the Year 4 vision); server-side reference implementations (App Attest verification, JWT interop) as documented companion code; token-exchange (RFC 8693); post-quantum primitives at parity with CryptoKit's support (adopted the release after Apple ships them); JWE if demand materialized ([BlurJWT roadmap](docs/modules/BlurJWT.md)).

**Acceptance criteria:** at least one shipping third-party integration through the plugin seams; multi-maintainer governance fully real (security-review rotation staffed by 3+); the annual maintenance scorecard ([MaintenanceStrategy §7](docs/MaintenanceStrategy.md)) published twice with all five facts green.

## Beyond — The Five-Year Vision

Standard-status: the assumed baseline for Apple-platform security, same-week OS support as routine, zero known-exploited vulnerabilities in released versions, and multiple organizations sharing stewardship. In full: [VISION.md](VISION.md).

---

*Per-module roadmaps (the "Future Roadmap" section of each [module spec](docs/modules/)) feed this file; conflicts resolve here. Unversioned ideas live in Discussions until they earn a release.*
