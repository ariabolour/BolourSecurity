# ``BlurSecurity``

Secure by design, Swifty by nature — the security foundation for modern Apple applications.

## Overview

BlurSecurity is a Swift 6, zero-third-party-dependency security platform (ADR-0002, `docs/adr/0002-zero-third-party-dependencies.md`) built from Apple's own SDKs: Keychain, cryptography, biometrics, certificate pinning, App Attest, JWT, and OAuth behind APIs designed so the secure path is the shortest path.

Ten composable modules share one vocabulary through [`BlurSecurityCore`](../blursecuritycore)'s protocol seams — import one module directly, or `import BlurSecurity` for all of them at once.

### Layer 0 — Foundation

- ``BlurSecurityCore`` — the shared vocabulary: protection policies, `SecureBytes`, typed errors, seams.

### Layer 1 — Primitives

- ``BlurCrypto`` — hashing, authenticated sealing, signing (software and Secure Enclave), key derivation.
- ``BlurKeychain`` — the keychain as it should have been: typed, async, redaction-safe.

### Layer 2 — Capabilities

- ``BlurBiometrics`` — Face ID, Touch ID, and Optic ID as one coherent policy API.
- ``BlurCertificates`` — X.509 parsing, trust evaluation, pinning policies that can't fail open.
- ``BlurSecureStorage`` — encrypted vaults and token custody.

### Layer 3 — Protocols & Services

- ``BlurNetworkSecurity`` — pinning and TLS policy enforced in `URLSession`, fail-closed.
- ``BlurJWT`` — JOSE with the algorithm-confusion vulnerability class made unrepresentable.
- ``BlurAppIntegrity`` — App Attest and DeviceCheck as one managed lifecycle.

### Layer 4 — Identity

- ``BlurOAuth`` — OAuth 2.1 and OpenID Connect with the deprecated flows simply absent.

## Getting Started

```swift
import BlurKeychain

let keychain = Keychain()
try await keychain.store(token, for: .refreshToken)   // device-only, unlocked-only, no sync
```

Each module's own documentation covers its full API, architecture, and the specific vulnerability classes it makes unrepresentable — start with whichever module matches the problem in front of you.
