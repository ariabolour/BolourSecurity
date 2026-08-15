# ADR-0006: Secure Enclave-first key design with explicit software fallback

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** founding maintainer
- **Security impact:** High — determines where private keys live by default
- **Also serves as:** this framework's Secure Enclave abstraction strategy — the "why `SecKey`
  and not CryptoKit's `SecureEnclave.P256.Signing.PrivateKey`" analysis lives in this ADR's
  "API surface" subsection below, rather than in a second, potentially conflicting document.

## Context

Apple silicon provides the Secure Enclave (SE): a hardware subsystem that generates and uses P-256 keys without the key material ever entering the application processor's memory. A key that cannot be read cannot be exfiltrated — not by memory dumps, not by backup extraction, not by the app's own bugs. Every device in our platform floor (iOS 16+, macOS 13+ on Apple silicon or T2, watchOS 9+, visionOS 1+) has one, with the narrow exception of older Intel Macs without a T2 chip.

The SE has real constraints: P-256 only (signing + ECIES-style agreement), keys are non-exportable and non-syncable, and operations require the device. A framework must decide whether hardware backing is the default developers fall into, or an option they must discover.

## Decision

**Hardware-backed is the default wherever the operation permits it; software keys are the explicit, visibly named choice.**

1. `BolourCrypto.SecureEnclaveKey` is the flagship key type for signing and key agreement. Guides, tutorials, and higher modules present it first.
2. Modules that need a device-bound key create SE keys by default: `BolourSecureStorage` vault master keys are SE-wrapped; `BolourAppIntegrity` uses App Attest's own SE-resident keys.
3. Software keys exist (interop, export, sync, non-P-256 algorithms are legitimate needs) but are created via APIs whose names carry the property: `SigningKey<A>.software()` — never a default parameter that silently degrades. A call site creating a software key *reads* as one.
4. On hardware without an SE (pre-T2 Intel Macs), `SecureEnclaveKey` creation throws `CryptoError.secureEnclaveUnavailable` — it never silently substitutes a software key. The error's recovery suggestion points to the explicit software API so the *developer* makes the fallback decision and owns it in code.
5. SE key references persist via the keychain as key handles; BolourKeychain and BolourCrypto share this representation through a Core seam.

## Alternatives Considered

- **Software-first with SE opt-in (industry default).** Matches raw-SDK ergonomics, but inverts our Law 1: the best available protection would require discovery. Rejected.
- **Automatic silent fallback SE → software.** Best availability story, catastrophic honesty story: the same line of code yields different security properties on different machines, and the developer never learns. Rejected — this is exactly the "convenient but not honest" API the Manifesto forbids.
- **SE-only, no software keys.** Purity at the cost of real use cases (JWKS interop, exportable backup keys, Ed25519). Rejected.

### API surface: `Security.framework`'s `SecKey` vs. CryptoKit's `SecureEnclave.P256.Signing.PrivateKey`

This decision also required choosing *which* Apple API creates and holds the Secure Enclave
key. Two exist for P-256 signing: the low-level `SecKey` (via `SecKeyCreateRandomKey` with
`kSecAttrTokenIDSecureEnclave`, what `SecureEnclaveKey` actually wraps today) and CryptoKit's
higher-level `SecureEnclave.P256.Signing.PrivateKey`. Recorded here as this ADR's answer to the
"why not the nicer Swift-native API" question, since it comes up in review:

| Dimension | `SecKey` (chosen) | CryptoKit `SecureEnclave.P256.Signing.PrivateKey` |
|---|---|---|
| **Persistence / lookup by tag** | `kSecAttrApplicationTag` + `SecItemCopyMatching` gives free, Keychain-backed lookup-by-name — exactly what `load(tag:)` needs | No tag-based lookup. The app must capture `dataRepresentation` and persist/re-supply it itself, typically via the Keychain — hand-rolling the persistence layer `SecKey` already provides |
| **Access-control requirements** | `SecAccessControlCreateWithFlags`, same vocabulary the rest of `BolourKeychain` uses | Accepts `SecAccessControl` too — comparable, no advantage either way |
| **Application-tag requirements** | Native (`kSecAttrApplicationTag`) | No equivalent; would be reinvented on top of wherever `dataRepresentation` is stored |
| **Portability** | `Security.framework`, identical across our platform floor | CryptoKit, equally available — no difference here |
| **API ergonomics** | C-bridged, stringly-typed attribute dictionaries, no compile-time key-name check | Genuinely nicer — a real Swift type, throwing initializers. CryptoKit's actual advantage |
| **Testability** | `SecureEnclaveProbe`'s gating need is identical either way (both need a real, entitled host) | Same |
| **Interop with the rest of the ecosystem** | `SecTrust`/`SecItem`/`BolourKeychain` all already speak `SecKey` — one vocabulary | A second private-key representation, needing conversion at every boundary |
| **Future migration risk** | Low — the same API Apple's own frameworks use internally | Low on its own terms; adopting it later would be a clean migration once the persistence gap above is accepted |

**`SecKey` stays** — not because CryptoKit is worse, but because tag-based persistence
surviving relaunches, in one vocabulary with `BolourKeychain`, is `SecKey`'s native strength and
CryptoKit's explicit gap. CryptoKit's nicer ergonomics would be spent re-solving a problem
`SecKey` already solves for free. An ephemeral, no-persistent-identity SE key would be a
legitimate, narrow case for CryptoKit's type — that's its own future ADR, not a reason to
replace `SecureEnclaveKey`'s persistent design.

## Consequences

- Easier: the default posture of apps built on BolourSecurity is hardware-bound keys; audits can grep for `software` to enumerate every deliberate exception.
- Harder: Intel-without-T2 Macs need an explicit code path in adopting apps that support them; docs must explain the SE's P-256-only constraint clearly.
- Security: private keys are non-exfiltratable by default; degradation is always attributable to a visible call site.

## Revisit When

Apple expands SE algorithm support (adjust defaults to match), or the macOS floor rises enough that non-SE Macs leave support.
