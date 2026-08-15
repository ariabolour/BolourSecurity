# Testing Strategy

A security control without a test proving it fails closed does not exist (Manifesto). This document defines the test tiers, the tools, and the gates. Framework: **Swift Testing** (`@Test`, `@Suite`, parameterized tests, tags) — no XCTest in new code, no third-party test dependencies ([ADR-0002](adr/0002-zero-third-party-dependencies.md)).

## 1. Test Tiers

**Tier 1 — Unit (every PR, all platforms in matrix).**
Pure logic: policy mappings (`ProtectionPolicy` → `kSec*`, `LAError` → `BiometricError`), parsers, state machines against scripted doubles, error taxonomies, format encodings. Fast, hermetic, exhaustive — table-driven parameterized tests are the house style. Every OS framework a module touches sits behind an internal protocol seam precisely so this tier can reach every branch, including the ones hardware makes rare (SE key invalidation, attestation revocation, biometry lockout).

**Tier 2 — Integration (every PR on macOS + simulator; device lanes nightly).**
Real OS backends: actual keychain round-trips, real `SecTrust` evaluation against generated test CAs, the local TLS harness (BolourNetworkSecurity), the local IdP harness (BolourOAuth), real vault files on disk with crash-injection. Hermetic by construction — every network endpoint a test touches is in-process; CI never depends on external services.

**Tier 3 — Device-required (nightly + release-gate, physical device farm).**
Tagged `.requiresDevice` (+ `.requiresBiometryEnrollment`, `.requiresAppAttestEntitlement`): Secure Enclave operations, App Attest against Apple's development environment, biometric UI lanes, large-payload vault streaming. Simulator runs of these suites assert the *honest degradation* (typed `unsupported`/`unavailable` errors) — the fallback behavior is itself specified behavior. **Current state, honestly:** `.requiresDevice` exists and is applied to the three suites that actually touch a real backend today (Keychain, Secure Enclave, `TokenStore`); `.requiresBiometryEnrollment`/`.requiresAppAttestEntitlement` are this tier's intended vocabulary but have no test to attach to yet, since Biometrics/AppIntegrity/OAuth have no real-hardware automated test at all — see [IntegrationTesting.md](IntegrationTesting.md) for the full, current-as-of-today breakdown and the manual verification checklist that covers the gap in the meantime.

**Tier 4 — Adversarial (bounded per-PR, extended nightly).**
- **Fuzzing:** the three hostile-input parsers — DER (BolourCertificates), JWT compact serialization (BolourJWT), `SealedMessage`/vault envelopes (BolourCrypto/BolourSecureStorage) — under a shared in-repo fuzzing harness (libFuzzer via SPM where toolchain allows; deterministic corpus replay as the PR-time floor). Invariants: no crash, no hang, no unbounded allocation, always a typed error. Corpora are checked in; every fuzz-found failure becomes a permanent regression case.
- **Attack corpus:** the curated known-attack fixtures (alg-confusion tokens, malformed chains, tampered ciphertexts, replayed assertions) asserted against *specific* typed errors — these suites are the executable form of our security claims.

**Tier 5 — Compile-time misuse tests.**
The pillar-2 guarantees ("this cannot compile") are tested as negative-compilation fixtures: source files expected to fail with specific diagnostics (`SecureBytes` is not `Codable`; claims access on `UnverifiedJWT` doesn't exist; single-pin `PinningPolicy` unconstructible). A guarantee enforced by the type system gets a test that the type system still enforces it.

## 2. Known-Answer & Interop Vectors

Crypto correctness is asserted against authority, not self-consistency: NIST CAVP (AES-GCM, SHA-2, HMAC, HKDF, PBKDF2), RFC 8032/8439/7515/7636 vectors, `openssl`-derived SPKI references, IdP-shaped OAuth fixtures. Vector files live in `Tests/Vectors/` with provenance headers.

## 3. Concurrency Testing

Strict concurrency ([ADR-0003](adr/0003-swift6-strict-concurrency.md)) proves data-race freedom; these suites prove *semantic* race freedom: refresh storms (one network refresh for N callers), keychain write storms (no torn state, no leaked `errSecDuplicateItem`), vault read-during-write, JWKS single-flight, prompt serialization. House pattern: `TaskGroup` storms with deterministic assertion of observable side-effect counts, run under TSan in the nightly lane.

## 4. Benchmarks

`Benchmarks/` tracks: seal/open throughput by payload size, SE signature latency, keychain op latency, JWT verify throughput, vault streaming throughput, PBKDF2 calibration drift. Nightly on fixed reference hardware; a >10% regression opens an issue automatically, and release notes publish the numbers. Benchmarks are honesty infrastructure — "production ready" includes "predictably fast."

## 5. Coverage & Gates

- Line coverage is a tripwire, not a target: **90% floor per module** enforced in CI, but review asks the better question — is every *claimed guarantee* exercised? The module spec's "Prevented:" list must map 1:1 to named test suites (`@Suite("Prevents nonce reuse")`), and that mapping is checked in release review.
- PR gate: Tier 1–2 green on the full platform matrix, Tier 4 bounded pass, Tier 5, coverage floor, TSan-clean on changed modules.
- Release gate: everything, plus Tier 3 device farm, extended fuzzing, benchmark comparison, and the format-compatibility suites (golden vaults/tokens from every prior release still open).

## 6. Test Code Standards

Test code is reviewed like production code: no sleeps (clock injection everywhere — `ContinuousClock` seams are part of module design), no order dependence, no shared mutable fixtures, suite names that read as specifications. A flaky test is a P1 bug against the test's owner; quarantining requires an issue with a fix date.
