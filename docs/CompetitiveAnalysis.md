# Competitive Analysis

An honest map of the field as of mid-2026. We respect these projects — several pioneered the space — and we name precisely the gap BolourSecurity fills: **no one offers a coherent, Swift-6-native, zero-dependency security platform across the full surface.** Everything below is a point solution, a port, or unmaintained.

## Keychain Wrappers

**KeychainAccess** (kishikawakatsumi) — the de-facto standard; enormous install base; pleasant fluent API. Gaps: Swift-5-era design (no strict concurrency, no typed throws, no async); stringly-typed keys; accessibility defaults mirror the SDK's (weaker than ours); secrets travel as `Data`/`String` (log-leak prone); maintenance cadence has slowed. *Lesson taken:* its ergonomics proved the demand; its defaults show why "wrapper" isn't enough.

**Valet** (Square) — opinionated and well-engineered; Secure Enclave-gated items done properly; corporate stewardship. Gaps: keychain-only mission (by design); ObjC-compatible API shape constrains Swiftiness; no crypto/JWT/OAuth story to compose with. *Closest in spirit; narrowest in scope.*

**Locksmith** — historically important, unmaintained for years, pre-dates modern Swift entirely. Its continued download numbers are evidence that this space retains users long after maintenance stops — an argument for our sustainability planning, not a competitor today.

## Crypto

**CryptoKit (Apple)** — not a competitor but the substrate; we curate it ([Manifesto Law 7](../MANIFESTO.md)). Its gaps are our surface: no keychain-integrated key custody story, no misuse-resistant envelope format, SE ergonomics that most developers never find.

**CryptoSwift** — pure-Swift implementations, huge adoption. Gaps that matter for us: software-only (no SE, no hardware backing), performance far below CryptoKit's hardware paths, and rolling your own primitives in Swift is precisely what our Law 7 forbids. Serves Linux/portability needs we deliberately don't target.

**swift-crypto / swift-certificates / swift-asn1 (Apple)** — excellent, server-focused; on Apple platforms they duplicate what the OS SDK provides. Per [ADR-0002](adr/0002-zero-third-party-dependencies.md) we don't link them; per that ADR's revisit clause we watch them — if Apple moves them into the OS SDK, we adapt.

## Identity & Tokens

**AppAuth-iOS (OpenID Foundation)** — the reference OAuth/OIDC client; certified, battle-tested. Gaps: Objective-C core with Java lineage (delegates, builders); token *storage is left to the app* — the most dangerous omission in practice; no PKCE-mandatory posture (configurable correctness). BolourOAuth's pitch against it: certified-grade protocol behavior *plus* custody, refresh single-flight, and Swift-6 API in one coherent unit.

**JOSESwift (Airside)** — solid JOSE implementation. Gaps: verification correctness is caller-assembled (algorithm choice, claims validation are the caller's job — exactly the historical vulnerability surface), no typed unverified/verified boundary, no first-class SE signing. 

**jwt-kit (Vapor)** — server-side Swift; not really in our lane but often reached for; no keychain/SE integration, Linux-first design.

## Pinning

**TrustKit (DataDog)** — the standard pinning kit; production-proven. Gaps: Objective-C, global-singleton configuration, swizzling-based integration option (at odds with our no-magic rule), fail-open configurable. Our structural answer: pins additive over system trust, mandatory backups by type, fail-closed with no configuration spelling for fail-open.

## App Integrity

No meaningful open-source wrapper exists for App Attest/DeviceCheck with lifecycle management — teams hand-roll the state machine against Apple's docs, and the common bugs (attest-once-forever, client-minted challenges) are visible in public code. `BolourAppIntegrity` has effectively no incumbent: **greenfield category.**

## The Standing Gap = Our Thesis

| Need | Incumbent answer | BolourSecurity answer |
|---|---|---|
| Keychain | KeychainAccess/Valet (point solutions) | BolourKeychain, composing with everything below |
| Crypto w/ hardware | Raw CryptoKit (finding SE is on you) | BolourCrypto, SE-first (ADR-0006) |
| Biometrics | Raw LAContext | BolourBiometrics (capability-typed results) |
| Pinning | TrustKit (ObjC, configurable fail modes) | BolourCertificates + BolourNetworkSecurity (fail-closed by type) |
| JWT | JOSESwift (assembly required) | BolourJWT (misuse unrepresentable) |
| OAuth + custody | AppAuth + "storage is your problem" | BolourOAuth + TokenStore, one unit |
| App integrity | Nothing | BolourAppIntegrity |
| **All of it, coherently** | **Nobody** | **The platform** |

The compound advantage is the ecosystem: every module strengthens the others (OAuth stores through SecureStorage, verifies through JWT, connects through NetworkSecurity, attests through AppIntegrity — sharing Core's vocabulary). Point solutions cannot match this without becoming us.

**What would genuinely threaten this thesis:** Apple shipping first-party Swifty umbrella APIs over these frameworks (see [RiskAnalysis](RiskAnalysis.md) — our posture: celebrate, adapt, deprecate overlap); or a well-funded competitor executing the same platform thesis faster (our moat is design quality and trust signals, which don't rush).

*Review cadence: this document is re-validated every six months and before each major release.*
