# ADR-0005: Consolidate the module ecosystem to eleven modules

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** founding maintainer (module set confirmed by project owner)
- **Security impact:** Low — organizational, but boundaries shape audit scope

## Context

The founding brief sketched fourteen candidate modules: BolourSecurityCore, BolourKeychain, BolourAuthentication, BolourBiometrics, BolourCrypto, BolourCertificates, BolourJWT, BolourOAuth, BolourSecureStorage, BolourAppAttest, BolourDeviceCheck, BolourNetworkingSecurity, BolourSigning, BolourUtilities — with the rule that each module must have one clear responsibility.

Applying that rule strictly, several candidates fail it: `BolourSigning` is a *capability of* cryptography, not a peer of it (CryptoKit itself treats signing as part of the crypto surface); `BolourUtilities` is by definition a module without one responsibility — grab-bag modules are where unreviewed helper code accumulates; `BolourAppAttest` and `BolourDeviceCheck` are two Apple services answering the same product question ("is this a legitimate instance of my app on a real device?") and are almost always adopted together; `BolourAuthentication` ambiguously spans local authentication (biometrics) and federated authentication (OAuth), two audiences that share no code.

## Decision

Ship eleven modules in five strict layers (see [Architecture.md §1–2](../Architecture.md)). Mapping from the original sketch:

| Original candidate | Disposition |
|---|---|
| BolourSecurityCore | Kept (Layer 0) |
| BolourCrypto | Kept (Layer 1) — **absorbs BolourSigning** |
| BolourKeychain | Kept (Layer 1) |
| BolourBiometrics | Kept (Layer 2) — **absorbs the local half of BolourAuthentication** |
| BolourCertificates | Kept (Layer 2) |
| BolourSecureStorage | Kept (Layer 2) |
| BolourNetworkingSecurity | Kept (Layer 3), **renamed `BolourNetworkSecurity`** (Apple's own term — "Network Security" — and the shorter compound reads better at `import`) |
| BolourJWT | Kept (Layer 3) |
| BolourAppAttest + BolourDeviceCheck | **Merged into `BolourAppIntegrity`** (Layer 3) — one product question, one module |
| BolourOAuth | Kept (Layer 4) — **absorbs the federated half of BolourAuthentication** |
| BolourSigning | Dissolved into BolourCrypto |
| BolourUtilities | **Deleted.** Genuinely shared vocabulary belongs in Core; anything else belongs in the module that uses it |
| — | **Added `BolourSecurity`** umbrella product for whole-ecosystem import |

## Alternatives Considered

- **Keep all fourteen as peers.** Maximum granularity, but three modules violate the one-responsibility rule from birth, the dependency graph gains no expressiveness, and every module is ~30% more documentation, testing, and release surface. Rejected.
- **Consolidate further (e.g. merge Keychain into SecureStorage).** Rejected: Keychain and encrypted-file storage have different threat models, different OS backends, and different audiences (a watch app wants Keychain alone). The line between Layer 1 and Layer 2 is real.

## Consequences

- Easier: every module states its mission in one sentence; audit scope per module is coherent; no junk-drawer module to police.
- Harder: developers searching for "device check" must discover `BolourAppIntegrity` — mitigated by DocC keywords, README module table, and a `DeviceCheckToken` type name that remains searchable.
- Security: fewer, stronger boundaries make review coverage measurable per module.

## Revisit When

A module's spec grows a second mission (split it), or Apple ships a new security framework warranting a new Layer 2/3 module (e.g. passkey management beyond AuthenticationServices' current surface).
