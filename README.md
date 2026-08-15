# BlurSecurity

**Secure by Design. Swifty by Nature.**

The security foundation for modern Apple applications — Keychain, cryptography, biometrics, certificate pinning, JWT, and OAuth behind elegant Swift 6 APIs that make the secure path the shortest path.

> **Status: v1.0, pre-audit.** All ten modules plus the umbrella package are implemented and tested against the design recorded in `docs/` — see [CHANGELOG](CHANGELOG.md) for what shipped and the [Known limitations](CHANGELOG.md#known-limitations) it names explicitly (device/hardware-gated round-trips, DocC site, audit). No independent security audit has been performed yet; treat this as a strong foundation to build on and review, not a finished, audited product. [ROADMAP](ROADMAP.md) covers what's next.

---

## Why BlurSecurity

Apple ships world-class security primitives. Using them correctly means hand-assembling `SecItemAdd` dictionaries, `LAContext` state, `SecTrust` callbacks, and JOSE parsing — and every app team rebuilds that layer, each with its own subtle mistakes. BlurSecurity is that layer, built once, built right:

- **Safe by default.** Configure nothing and get device-only keychain items, authenticated encryption with fresh nonces, fail-closed pinning, Secure Enclave-backed keys. Weakening a guarantee requires an API whose *name* says so — `unsafe`, `unvalidated`, `software` — visible in every code review and every `grep`.
- **Impossible to hold wrong.** The type system does the enforcing: an unverified JWT has no claims accessor; a nonce cannot be reused because no API accepts one; a pinning policy without backup pins does not compile; deprecated OAuth flows have no spelling at all.
- **Swifty to the bone.** Swift 6 strict concurrency, `async/await` only, typed throws, value semantics, zero singletons — APIs that read like the [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/) wrote them.
- **A platform, not a wrapper.** Ten composable modules that share one vocabulary and strengthen each other — import one, or import them all.
- **Zero third-party dependencies. Permanently.** Our supply chain is Apple's SDKs, [by architectural decision](docs/adr/0002-zero-third-party-dependencies.md).

## A Taste

```swift
import BlurKeychain

let keychain = Keychain()
try await keychain.store(token, for: "refresh-token")   // device-only, unlocked-only, no sync —
                                                        // you did it right by accident
```

```swift
import BlurSecureStorage
import BlurBiometrics

let context = try await BiometricAuthenticator().authenticate(reason: .init(verbatim: "Unlock your health records"))
let vault = try await Vault.open(named: "HealthRecords", presence: .biometry(), context: context)
try await vault.write(reportPDF, to: "reports/2026-08.pdf")
```

```swift
import BlurOAuth

let session = try await client.signIn(presentingFrom: anchor)      // Code + PKCE, verified ID token
let header = try await session.tokens.validAccessToken().headerValue  // single-flight refresh, managed custody
```

## The Modules

| Module | One-line mission |
|---|---|
| [`BlurSecurityCore`](docs/modules/BlurSecurityCore.md) | The shared vocabulary: protection policies, `SecureBytes`, typed errors, seams |
| [`BlurCrypto`](docs/modules/BlurCrypto.md) | Hashing, sealing, signing, key agreement — Secure Enclave first |
| [`BlurKeychain`](docs/modules/BlurKeychain.md) | The keychain as it should have been |
| [`BlurBiometrics`](docs/modules/BlurBiometrics.md) | Face ID, Touch ID, Optic ID as one coherent policy API |
| [`BlurCertificates`](docs/modules/BlurCertificates.md) | X.509, trust evaluation, pinning policies that can't fail open |
| [`BlurSecureStorage`](docs/modules/BlurSecureStorage.md) | Encrypted vaults and token custody with a hardware-backed key hierarchy |
| [`BlurNetworkSecurity`](docs/modules/BlurNetworkSecurity.md) | Pinning and TLS policy enforced in URLSession, fail-closed |
| [`BlurJWT`](docs/modules/BlurJWT.md) | JOSE with the vulnerability catalog made unrepresentable |
| [`BlurAppIntegrity`](docs/modules/BlurAppIntegrity.md) | App Attest + DeviceCheck as one managed lifecycle |
| [`BlurOAuth`](docs/modules/BlurOAuth.md) | OAuth 2.1 + PKCE + OIDC with token lifecycle built in |
| [`BlurSecurity`](docs/modules/BlurSecurity.md) | The whole platform behind one `import` |

**Platforms:** iOS 16+ · iPadOS 16+ · macOS 13+ · watchOS 9+ · visionOS 1+  **Toolchain:** Swift 6, strict concurrency, Swift Package Manager.

## Documentation Map

- [Vision](VISION.md) · [Manifesto & Engineering Principles](MANIFESTO.md) · [Roadmap](ROADMAP.md)
- [Architecture](docs/Architecture.md) and [Architecture Decision Records](docs/adr/)
- [API Design Philosophy](docs/APIDesignPhilosophy.md) — the five pillars and the review checklist
- Strategy: [Documentation](docs/DocumentationStrategy.md) · [Testing](docs/TestingStrategy.md) · [CI/CD](docs/CICDStrategy.md) · [Releases](docs/ReleaseStrategy.md) · [Developer Experience](docs/DeveloperExperience.md) · [Adoption](docs/AdoptionStrategy.md) · [Competitive Analysis](docs/CompetitiveAnalysis.md) · [Risk Analysis](docs/RiskAnalysis.md) · [Maintenance](docs/MaintenanceStrategy.md)

## Contributing & Security

- [CONTRIBUTING.md](CONTRIBUTING.md) — new API starts with its call sites, in public, before implementation. [GOVERNANCE.md](GOVERNANCE.md) covers how decisions are made; the [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) covers how we treat each other.
- **Vulnerabilities:** never in public issues — see [SECURITY.md](SECURITY.md) for private reporting and our 48-hour response commitment.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [ADR-0007](docs/adr/0007-apache-2.0-license.md) for the reasoning.

---

*Built to a single standard: would this make Apple's framework engineers proud?*
