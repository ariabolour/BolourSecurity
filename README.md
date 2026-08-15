# BolourSecurity

**Secure by Design. Swifty by Nature.**

The security foundation for modern Apple applications — Keychain, cryptography, biometrics, certificate pinning, JWT, and OAuth behind elegant Swift 6 APIs that make the secure path the shortest path.

> **Status: 0.9.0-beta, pre-audit, pre-1.0.** Every module planned for 1.0 is implemented and unit-tested against the design recorded in `docs/` — see [CHANGELOG](CHANGELOG.md) for what shipped and the [Known limitations](CHANGELOG.md#known-limitations) it names explicitly. What "beta" means concretely: no independent security audit; no real-device test execution in CI (Keychain/Secure Enclave round-trips run against the real backend but only where a local probe finds one — Biometrics, App Attest, and real OAuth sessions have no automated hardware coverage at all yet, gated or otherwise — see [Integration Testing](docs/IntegrationTesting.md)); no published DocC site; and no external adopters yet. Treat this as a strong, actively-hardened foundation to build on and review — not a finished, audited, production-proven product. [ROADMAP](ROADMAP.md#whats-required-before-100) names exactly what's required before 1.0.0.

---

## Why BolourSecurity

Apple ships world-class security primitives. Using them correctly means hand-assembling `SecItemAdd` dictionaries, `LAContext` state, `SecTrust` callbacks, and JOSE parsing — and every app team rebuilds that layer, each with its own subtle mistakes. BolourSecurity is an attempt to build that layer once, deliberately, and be honest about how far it's gotten:

- **Safe by default.** Configure nothing and get device-only keychain items, authenticated encryption with fresh nonces, fail-closed pinning, Secure Enclave-backed keys. Weakening a guarantee requires an API whose *name* says so — `unsafe`, `unvalidated`, `software` — visible in every code review and every `grep`.
- **Hard to hold wrong.** The type system does the enforcing where it can, so dangerous states are harder to represent, not merely discouraged in a comment: an unverified JWT has no claims accessor; a nonce cannot be reused because no API accepts one; a pinning policy without backup pins does not compile; deprecated OAuth flows have no spelling at all. This narrows a real class of mistakes — it is not a claim that misuse is impossible or that the framework has been proven correct.
- **Swifty to the bone.** Swift 6 strict concurrency, `async/await` only, typed throws, value semantics, zero singletons — APIs that read like the [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/) wrote them.
- **A platform, not a wrapper.** Ten composable modules that share one vocabulary and strengthen each other — import one, or import them all.
- **Zero third-party dependencies. Permanently.** Our supply chain is Apple's SDKs, [by architectural decision](docs/adr/0002-zero-third-party-dependencies.md).

## A Taste

```swift
import BolourKeychain

let keychain = Keychain()
try await keychain.store(token, for: "refresh-token")   // device-only, unlocked-only, no sync —
                                                        // you did it right by accident
```

```swift
import BolourSecureStorage
import BolourBiometrics

let context = try await BiometricAuthenticator().authenticate(reason: .init(verbatim: "Unlock your health records"))
let vault = try await Vault.open(named: "HealthRecords", presence: .biometry(), context: context)
try await vault.write(reportPDF, to: "reports/2026-08.pdf")
```

```swift
import BolourOAuth

let session = try await client.signIn(presentingFrom: anchor)      // Code + PKCE, verified ID token
let header = try await session.tokens.validAccessToken().headerValue  // single-flight refresh, managed custody
```

## The Modules

| Module | One-line mission |
|---|---|
| [`BolourSecurityCore`](docs/modules/BolourSecurityCore.md) | The shared vocabulary: protection policies, `SecureBytes`, typed errors, seams |
| [`BolourCrypto`](docs/modules/BolourCrypto.md) | Hashing, sealing, signing, key agreement — Secure Enclave first |
| [`BolourKeychain`](docs/modules/BolourKeychain.md) | The keychain as it should have been |
| [`BolourBiometrics`](docs/modules/BolourBiometrics.md) | Face ID, Touch ID, Optic ID as one coherent policy API |
| [`BolourCertificates`](docs/modules/BolourCertificates.md) | X.509, trust evaluation, pinning policies that can't fail open |
| [`BolourSecureStorage`](docs/modules/BolourSecureStorage.md) | Encrypted vaults and token custody with a hardware-backed key hierarchy |
| [`BolourNetworkSecurity`](docs/modules/BolourNetworkSecurity.md) | Pinning and TLS policy enforced in URLSession, fail-closed |
| [`BolourJWT`](docs/modules/BolourJWT.md) | JOSE with the vulnerability catalog made unrepresentable |
| [`BolourAppIntegrity`](docs/modules/BolourAppIntegrity.md) | App Attest + DeviceCheck as one managed lifecycle |
| [`BolourOAuth`](docs/modules/BolourOAuth.md) | OAuth 2.1 + PKCE + OIDC with token lifecycle built in |
| [`BolourSecurity`](docs/modules/BolourSecurity.md) | The whole platform behind one `import` |

**Platforms:** iOS 16+ · iPadOS 16+ · macOS 13+ · watchOS 9+ · visionOS 1+  **Toolchain:** Swift 6, strict concurrency, Swift Package Manager.

## Module Maturity

Not every module carries the same weight of scrutiny. "Stable Candidate" describes design maturity and API-surface stability under active internal review — not a stability *promise*; per [SemVer](https://semver.org), nothing is API-stable pre-1.0.0, and no module below has had independent security review or real-device test execution yet (see [Integration Testing](docs/IntegrationTesting.md) and the [1.0 gate](ROADMAP.md#whats-required-before-100)).

| Module | Maturity | Why |
|---|---|---|
| `BolourSecurityCore` | Stable Candidate | Foundational vocabulary every other module depends on; smallest, most-reviewed surface |
| `BolourKeychain` | Stable Candidate | Thin, well-understood mapping over a single Apple API (`SecItem*`) |
| `BolourBiometrics` | Stable Candidate | Thin mapping over `LAContext`; policy surface is small |
| `BolourCrypto` | Stable Candidate | Composes CryptoKit/Security primitives directly; no invented cryptography |
| `BolourSecureStorage` | Stable Candidate | Built directly on the above four; master-key handling is the one open item (see [Known limitations](CHANGELOG.md#known-limitations)) |
| `BolourCertificates` | Beta | Custom DER/X.509 parsing is inherently higher-risk code; trust decisions are delegated to `SecTrust`, but the parser itself needs more adversarial-input hardening before "stable" |
| `BolourNetworkSecurity` | Beta | Depends on Certificates' maturity; TLS-floor enforcement has one documented structural gap (see module doc) |
| `BolourJWT` | Beta | Correct on direct audit (algorithm confusion, `alg: none` structurally unreachable), but JOSE parsing is adversarial-input-facing and wants more fuzzing before "stable" |
| `BolourOAuth` | Beta | Depends on JWT + NetworkSecurity's maturity; the highest-complexity control flow (PKCE, single-flight refresh, rotation) in the ecosystem |
| `BolourAppIntegrity` | Beta, leaning Experimental | The most hardware/entitlement/Apple-server-dependent module; cannot be meaningfully exercised without a real device and a real App Attest environment |
| `BolourSecurity` (umbrella) | Beta | Tracks the least mature module it re-exports |

## Documentation Map

- [Vision](VISION.md) · [Manifesto & Engineering Principles](MANIFESTO.md) · [Roadmap](ROADMAP.md)
- [**Threat Model**](THREAT_MODEL.md) — assets, threat actors, explicit non-goals, and a per-module guarantee/mitigation table. Start here if you're assessing this framework for a security-sensitive integration.
- [Architecture](docs/Architecture.md) and [Architecture Decision Records](docs/adr/)
- [API Design Philosophy](docs/APIDesignPhilosophy.md) — the five pillars and the review checklist
- [Integration Testing](docs/IntegrationTesting.md) — what's device-tested today, what isn't, and how to verify hardware-dependent paths yourself
- Strategy: [Documentation](docs/DocumentationStrategy.md) · [Testing](docs/TestingStrategy.md) · [CI/CD](docs/CICDStrategy.md) · [Releases](docs/ReleaseStrategy.md) · [Developer Experience](docs/DeveloperExperience.md) · [Adoption](docs/AdoptionStrategy.md) · [Competitive Analysis](docs/CompetitiveAnalysis.md) · [Risk Analysis](docs/RiskAnalysis.md) · [Maintenance](docs/MaintenanceStrategy.md)

## Contributing & Security

- [CONTRIBUTING.md](CONTRIBUTING.md) — new API starts with its call sites, in public, before implementation. [GOVERNANCE.md](GOVERNANCE.md) covers how decisions are made; the [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) covers how we treat each other.
- **Vulnerabilities:** never in public issues — see [SECURITY.md](SECURITY.md) for private reporting and our 48-hour response commitment.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [ADR-0007](docs/adr/0007-apache-2.0-license.md) for the reasoning.

---

*Built to a single standard: would this make Apple's framework engineers proud?*
