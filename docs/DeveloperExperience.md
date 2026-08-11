# Developer Experience Strategy

The package should be enjoyable. DX is not polish applied at the end; it is a design input with its own review criteria. The measure: **time-to-first-secure-win under five minutes, and no dead ends after that.**

## 1. The First Five Minutes

The adoption funnel is designed end to end:

1. README shows a real, complete, three-line win (store a secret) above the fold.
2. `Package.swift` add → `import BlurKeychain` → autocomplete carries the developer: `Keychain(` shows a zero-argument path; `store(` reads as a sentence; nothing requires reading docs to be *correct* (docs exist to make you *informed*).
3. The *Store Your First Secret* tutorial confirms what just happened and — critically — explains the security properties the developer already got for free. The "you did it right by accident" moment is the brand promise made tangible.

## 2. Autocomplete as a UX Surface

- Entry-point types are guessable nouns: `Keychain`, `Vault`, `BiometricAuthenticator`, `TrustEvaluator`, `JWTVerifier`, `OAuthClient`. A developer who types what they want finds it.
- Method families are designed for the completion popover: short base names, disambiguation in labels (`store(_:for:presence:)`), defaults ordered so the common call is the shortest.
- Factory methods live on the produced type (`SymmetricKey.random()`, `SPKIHash(base64Encoded:)`) so discovery follows the type you already have or want.
- Doc summary lines are written to be read *in the popover*: front-loaded, one sentence, no markup dependence.

## 3. Error Messages as Support Staff

Errors follow a house format enforced in review ([ADR-0004](adr/0004-typed-throws-error-architecture.md)): what failed → likely cause → next step. The catalog of `errorDescription`/`recoverySuggestion` strings is itself a reviewed artifact — we write them the way Apple writes good compiler diagnostics. The canonical example is `KeychainError.accessGroupDenied`, which converts the ecosystem's most notorious silent failure (`-34018`) into instructions. Rule of thumb: **every error string should save its reader a web search.**

## 4. Minimal Boilerplate, No Magic

- Zero-configuration constructors everywhere the default is defensible; configuration objects are plain values you can build in one place and inject.
- No required base classes, no protocol ceremonies to adopt, no setup calls before first use, no AppDelegate hooks.
- Convenience layers (`@KeychainStored`) are sugar *over* the core API with documented semantics — never a parallel system with different behavior.
- Where ceremony is irreducible because security demands it (server challenges for attestation, backup pins for pinning), the API states why in its documentation instead of pretending, and the tutorial shows the full honest flow.

## 5. Example Applications

Two example apps ship in-repo and are built in CI (they cannot rot):

- **SecureNotes** — local-first: `Vault` + `BlurBiometrics` + `BlurKeychain`. The "protect data on this device" story.
- **SignInDemo** — service-connected: `BlurOAuth` + `BlurJWT` + `BlurNetworkSecurity` + `BlurAppIntegrity`, against a tiny bundled mock server. The "prove and connect" story.

Example code is held to production standard — people ship what they paste. Each screen links (comment header) to the tutorial section it embodies.

## 6. Predictability Rules

- The same concept has the same name everywhere (`ProtectionPolicy`, `presence:`, `context:` mean identical things in every module).
- The same shape solves the same problem: parse → typed value; evaluate/verify → typed proof; store → `ItemKey`-addressed; every service → instance you create, not singleton you summon.
- No behavioral flags that change what other calls mean at a distance; configuration is local to the value you hold.

## 7. Feedback Loops

- "First-win friction" issue label with priority triage: any report of confusion inside the five-minute funnel is treated as a defect, not a docs request.
- Quarterly DX review: walk the funnel fresh on a clean machine, popover audit (read every entry-point summary line in Xcode), error-string audit against the house format.
- API sketches for new surface are posted as discussion threads *before* implementation (see [CONTRIBUTING](../CONTRIBUTING.md)) — community reads call sites first, exactly the order users will experience them.
