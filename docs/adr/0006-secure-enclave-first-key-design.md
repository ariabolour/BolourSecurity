# ADR-0006: Secure Enclave-first key design with explicit software fallback

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** founding maintainer
- **Security impact:** High — determines where private keys live by default

## Context

Apple silicon provides the Secure Enclave (SE): a hardware subsystem that generates and uses P-256 keys without the key material ever entering the application processor's memory. A key that cannot be read cannot be exfiltrated — not by memory dumps, not by backup extraction, not by the app's own bugs. Every device in our platform floor (iOS 16+, macOS 13+ on Apple silicon or T2, watchOS 9+, visionOS 1+) has one, with the narrow exception of older Intel Macs without a T2 chip.

The SE has real constraints: P-256 only (signing + ECIES-style agreement), keys are non-exportable and non-syncable, and operations require the device. A framework must decide whether hardware backing is the default developers fall into, or an option they must discover.

## Decision

**Hardware-backed is the default wherever the operation permits it; software keys are the explicit, visibly named choice.**

1. `BlurCrypto.SecureEnclaveKey` is the flagship key type for signing and key agreement. Guides, tutorials, and higher modules present it first.
2. Modules that need a device-bound key create SE keys by default: `BlurSecureStorage` vault master keys are SE-wrapped; `BlurAppIntegrity` uses App Attest's own SE-resident keys.
3. Software keys exist (interop, export, sync, non-P-256 algorithms are legitimate needs) but are created via APIs whose names carry the property: `SigningKey(software:)` / `P256.SigningKey.softwareKey()` — never a default parameter that silently degrades. A call site creating a software key *reads* as one.
4. On hardware without an SE (pre-T2 Intel Macs), `SecureEnclaveKey` creation throws `CryptoError.secureEnclaveUnavailable` — it never silently substitutes a software key. The error's recovery suggestion points to the explicit software API so the *developer* makes the fallback decision and owns it in code.
5. SE key references persist via the keychain as key handles; BlurKeychain and BlurCrypto share this representation through a Core seam.

## Alternatives Considered

- **Software-first with SE opt-in (industry default).** Matches raw-SDK ergonomics, but inverts our Law 1: the best available protection would require discovery. Rejected.
- **Automatic silent fallback SE → software.** Best availability story, catastrophic honesty story: the same line of code yields different security properties on different machines, and the developer never learns. Rejected — this is exactly the "convenient but not honest" API the Manifesto forbids.
- **SE-only, no software keys.** Purity at the cost of real use cases (JWKS interop, exportable backup keys, Ed25519). Rejected.

## Consequences

- Easier: the default posture of apps built on BlurSecurity is hardware-bound keys; audits can grep for `software` to enumerate every deliberate exception.
- Harder: Intel-without-T2 Macs need an explicit code path in adopting apps that support them; docs must explain the SE's P-256-only constraint clearly.
- Security: private keys are non-exfiltratable by default; degradation is always attributable to a visible call site.

## Revisit When

Apple expands SE algorithm support (adjust defaults to match), or the macOS floor rises enough that non-SE Macs leave support.
