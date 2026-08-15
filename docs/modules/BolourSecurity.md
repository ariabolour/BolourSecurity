# BolourSecurity (Umbrella)

**Umbrella product.** The whole ecosystem behind one `import`.

## Mission

Give apps that adopt the full platform a single import and a single mental model, without costing narrowly-scoped apps anything: the umbrella adds no types, no behavior, and no policy — it re-exports.

## Responsibilities

- `@_exported import` of all ten modules. Nothing else. The umbrella target's only source file is the list of re-exports.
- Host the ecosystem-level DocC catalog: the "Meet BolourSecurity" landing page, cross-module tutorials (the SecureNotes and SignInDemo walkthroughs), the security-considerations overview, and the module directory.

## Public API

```swift
// The entire source of the umbrella target:
@_exported import BolourSecurityCore
@_exported import BolourCrypto
@_exported import BolourKeychain
@_exported import BolourBiometrics
@_exported import BolourCertificates
@_exported import BolourSecureStorage
@_exported import BolourNetworkSecurity
@_exported import BolourJWT
@_exported import BolourAppIntegrity
@_exported import BolourOAuth
```

No umbrella-only symbols, ever. A type that "belongs to the whole platform" belongs in Core; convenience that spans modules belongs in the highest module involved, or in documentation. This rule keeps the umbrella from becoming a junk drawer with good branding.

## Dependencies

All ten modules. Nothing from Apple directly.

## Architecture

- Because the umbrella is pure re-export, importing it is *semantically identical* to importing every module — same symbols, same documentation, no wrapper indirection to confuse jump-to-definition.
- Binary-size guidance in docs: SPM links only what you use, but review-conscious teams (banking, government) may prefer narrow imports so their dependency surface is enumerable in the diff; both patterns are first-class.

## Usage Example

```swift
import BolourSecurity   // everything

let keychain = Keychain()
let vault = try await Vault.open(named: "Documents")
let session = try await oauthClient.signIn(presentingFrom: anchor)
```

## Testing Strategy

- A compile-time smoke test target that `import BolourSecurity` and touches one symbol from each module (catches a dropped re-export at CI time).
- DocC build of the umbrella catalog is a release gate (broken cross-module links fail CI).

## Security Considerations & Common Mistakes Prevented

- None of its own — by design. The umbrella cannot weaken anything because it defines nothing.

## Future Roadmap

- Tracks the ecosystem. The umbrella changes only when a module is added (major/minor event per ReleaseStrategy) — and such additions are re-export additions only.
