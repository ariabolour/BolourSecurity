# API Design Philosophy

Every public symbol in BlurSecurity is designed against the [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/), then held to a stricter standard: **the API must make the secure path the shortest path, and the insecure path a visible decision.** This document defines the five pillars, the naming system, and the review checklist every API PR must pass.

All Swift in this document is *signature-level design*, not implementation.

## Pillar 1 — Safe by Default

A developer who configures nothing gets our strongest reasonable posture. Defaults are part of the security model and are individually documented and reviewed.

```swift
// The zero-decision call site is the secure one:
let keychain = Keychain(service: "com.example.app")
try await keychain.store(token, for: .refreshToken)
// → kSecAttrAccessibleWhenUnlockedThisDeviceOnly, non-synchronizable,
//   this app's default access group. Every relaxation is explicit:

let shared = Keychain(
    service: "com.example.app",
    protection: .afterFirstUnlock,          // visible decision
    synchronizability: .synchronizable      // visible decision
)
```

Canonical defaults across the ecosystem:

| Surface | Default | To weaken, you must write |
|---|---|---|
| Keychain items | `.whenUnlockedThisDeviceOnly`, no iCloud sync | `protection:` / `synchronizability:` argument |
| Symmetric encryption | AES-GCM, fresh random nonce per message | (no API reuses a nonce; deterministic nonces don't exist in the public surface) |
| Signing / agreement keys | Secure Enclave-backed ([ADR-0006](adr/0006-secure-enclave-first-key-design.md)) | `software`-named initializer |
| Certificate pinning | Fail closed; system trust still required underneath pins | `Unvalidated`-named escape hatch |
| JWT verification | `exp`/`nbf` enforced, issuer + audience required, algorithm allowlist | explicit `.allowing(...)` policy edits |
| OAuth | Authorization Code + PKCE (S256) only | (no API offers implicit or plain-PKCE flows at all) |
| Biometric auth | Current-set biometry (invalidated on re-enrollment) | `.anyEnrolled` policy |

Two corollaries:

- **Absence beats opt-out.** Where a practice is indefensible (implicit grant, ECB mode, `alg: none`), we do not ship it behind a flag. It simply does not exist.
- **Weakening never hides in a boolean.** `allowInsecure: true` tells a reviewer nothing. Named types and argument labels carry the meaning: `.trust(.unvalidatedForDebugBuilds)` is greppable and self-indicting.

## Pillar 2 — Impossible to Misuse

The type system eliminates bug classes rather than documenting them.

**Distinct types for distinct secrets.** Keys, nonces, digests, tokens, and passwords are never bare `Data` or `String`:

```swift
public struct SymmetricKey: Sendable { … }         // not Data
public struct Nonce: Sendable { … }                // not Data
public struct SPKIHash: Sendable { … }             // not String
public struct AuthorizationCode: Sendable { … }    // not String
```

You cannot pass a password where a key belongs; you cannot pin a hostname string where an SPKI hash belongs. Conversions exist but are named, lossy-aware, and documented.

**States are types.** Operations that change trust status change *type*, so unchecked data cannot flow where checked data is required:

```swift
// An unverified JWT has no claims accessor. Verification is the only door.
public struct UnverifiedJWT: Sendable {
    public var unverifiedHeader: JWTHeader { get }   // name warns at every use
}
public struct VerifiedJWT<Claims: JWTClaims>: Sendable {
    public var claims: Claims { get }                // only exists post-verification
}
public struct JWTVerifier: Sendable {
    public func verify<C: JWTClaims>(
        _ token: UnverifiedJWT, as _: C.Type
    ) throws(JWTError) -> VerifiedJWT<C>
}
```

The same pattern recurs everywhere trust changes hands: `Certificate` vs `EvaluatedCertificateChain`; `AttestationRequest` vs `Attestation`; biometric success returning a scoped `AuthenticatedContext` rather than a `Bool` someone can accidentally invert.

**Phantom types bind keys to their algebra.**

```swift
public struct SigningKey<Curve: SigningCurve>: Sendable { … }
public struct VerificationKey<Curve: SigningCurve>: Sendable { … }
public struct Signature<Curve: SigningCurve>: Sendable { … }
// A P256 signature cannot be verified with an Ed25519 key — it doesn't type-check.
```

**Secrets don't leak through reflection.** `SecureBytes` and every secret-bearing type implement `description`/`debugDescription` as redacted (`"SecureBytes(32 bytes, redacted)"`), and their conformance to `Codable` (where it exists at all) is deliberate and documented.

## Pillar 3 — Swifty

We follow the Swift API Design Guidelines to the letter — clarity at the point of use, fluent grammatical call sites, omit needless words — and adopt modern Swift wholesale:

- **`async/await` only.** No completion handlers, no delegate-required flows in public API. Where the OS speaks delegate (URLSession auth challenges), BlurSecurity adapts internally.
- **Typed throws** per [ADR-0004](adr/0004-typed-throws-error-architecture.md).
- **Value semantics** for everything without genuine identity; the three sanctioned actors are listed in [Architecture.md §6](Architecture.md).
- **No public singletons.** `Keychain`, `Vault`, `BiometricAuthenticator`, `OAuthClient` are instances the app creates, owns, and injects — testable by construction.
- **Grammar rules from the Guidelines**, applied consistently: mutating/nonmutating pairs (`seal`/`sealed`), side-effect-free values read as nouns (`digest`, `claims`), argument labels that make call sites read as sentences:

```swift
let sealed  = try key.seal(message)
let opened  = try key.open(sealed)
let sig     = try await enclaveKey.signature(for: digest)
let session = try await client.signIn(presentingFrom: anchor)
let ok      = verifier.isValidSignature(sig, for: digest)
```

- **Property-wrapper sugar where it genuinely fits** (synchronous, non-throwing reads of cached keychain state) is layered *on top of* the core API, never a replacement for it, and documented with its exact semantics (`@KeychainStored` in the BlurKeychain spec).

## Pillar 4 — Composable

- Each product imports alone and works alone (dependency rules in [Architecture.md §3](Architecture.md)).
- Cross-module needs are protocol seams defined in Core (`SecretStore`, `TrustEvaluating`, …) so any conforming implementation — including a test double — slots in:

```swift
// BlurOAuth doesn't know about BlurSecureStorage. It knows about the seam:
public struct OAuthClient: Sendable {
    public init(
        configuration: OAuthConfiguration,
        tokenStore: some SecretStore    // TokenStore conforms; so does InMemoryStore in tests
    )
}
```

- Configuration composes as values: policies are structs you build once, test in isolation, and hand to many call sites.

## Pillar 5 — Production Ready

- Every public symbol: DocC-documented (enforced in CI), covered by Swift Testing suites including failure paths, and benchmark-tracked where on a hot path.
- API stability follows [ReleaseStrategy.md](ReleaseStrategy.md): no breaking changes outside majors; `@_spi(Experimental)` for pre-stable surface.
- Errors are designed for incident response: what failed, likely cause, recovery — never secret material ([ADR-0004](adr/0004-typed-throws-error-architecture.md)).
- Localization-ready user-facing strings (biometric prompt reasons) are typed (`AuthenticationReason`), not raw strings, so they can't be forgotten.

## Naming System

- **Modules:** `Blur` + capability noun (`BlurKeychain`). No abbreviations.
- **Types:** plain nouns without prefixes — inside `BlurKeychain`, the type is `Keychain`, not `BlurKeychain` or `BLRKeychain`. Swift module namespacing exists; we use it. Collisions with Apple types are avoided by choosing more precise nouns (our CryptoKit-adjacent types pick names CryptoKit doesn't use, e.g. `SealedMessage`, `SecureEnclaveKey`).
- **The `unsafe`/`unvalidated`/`software` lexicon** is reserved: those words appear in a name if and only if the API weakens a guarantee, and every guarantee-weakening API contains one of them.
- **`unverified` prefix** on any accessor exposing data before trust evaluation (`unverifiedHeader`, `unverifiedPayloadClaims`).
- Factory methods on the *produced* type (`SymmetricKey.random()`, `Nonce.random()`); conversions as initializers (`SPKIHash(base64Encoded:)`).

## The API Review Checklist

Every PR adding or changing public API must answer in the PR description:

1. What is the zero-configuration behavior, and is it the most secure reasonable behavior?
2. Can this API be called incorrectly in a way that compiles? If yes, why can't the type system prevent it?
3. Does any parameter weaken a guarantee? Is the weakening visible in the *name*, not just a value?
4. Does the call site read as a sentence under the Swift API Design Guidelines?
5. Is the failure domain typed, and does every error case teach?
6. Is anything secret printable, `Codable`, or reflectable through this API?
7. What does the DocC summary line say? (One sentence, no caveats needed = good design signal.)
8. Craig test: would this signature look at home on an Apple framework diff?
