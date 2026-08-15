# Threat Model

What BolourSecurity protects against, who it protects against, and what it explicitly doesn't
claim to do. Where this document and a module's own DocC disagree, this document wins.

This is an internal, self-authored threat model — a starting point for your own risk
assessment, not a substitute for one, and not an independent security audit. See
[SECURITY.md](SECURITY.md) and the [1.0 gate checklist](ROADMAP.md#whats-required-before-100).

## Assets

| Asset | Primary module(s) |
|---|---|
| Credentials (passwords, API keys) at rest | `BolourKeychain` |
| Refresh tokens | `BolourOAuth` (custody via `BolourSecureStorage`/`BolourKeychain`) |
| Access tokens (bearer JWTs and otherwise) | `BolourJWT`, `BolourOAuth` |
| Private signing/agreement keys | `BolourCrypto` (`SecureEnclaveKey`, software `SigningKey`) |
| Symmetric encryption keys | `BolourCrypto`, `BolourSecureStorage` (vault key hierarchy) |
| Certificate pins (integrity-critical, not secret) | `BolourCertificates`, `BolourNetworkSecurity` |
| Identity data (claims, biometric-authenticated context) | `BolourBiometrics`, `BolourJWT` |
| Signed payloads and attestation/assertion objects | `BolourAppIntegrity` |
| Encrypted files and their manifests | `BolourSecureStorage` |

## Threat Actors

- **Malicious local applications** — another app reading this app's Keychain items, files, or
  memory. Mitigated by device-only, app-scoped Data Protection defaults and SE key
  non-exportability.
- **A stolen, locked device.** Mitigated by `.whenUnlockedThisDeviceOnly`-class protection being
  the default everywhere a weaker class requires an explicit, named opt-in.
- **Network attackers** (on-path, MITM, hostile Wi-Fi) — mitigated by fail-closed certificate
  pinning layered over system trust, plus TLS-floor enforcement.
- **Reverse engineers** — binary access, static/dynamic analysis, but not a live unlocked
  device. SE key material is genuinely unextractable from a binary and `SecureBytes` reduces
  what a casual string search finds; this is not a defense against a debugger attached to a
  *running* process (see Non-Goals).
- **Malicious or compromised backend responses** — hostile certificates, `alg: none`/confused
  JWTs, adversarial DER. Every parser here throws a typed error on malformed input; it never
  crashes, hangs, or over-allocates (see the DER/JWT fuzz suites).
- **Stolen-device attackers with time** — forensic extraction, jailbreak exploits, brute-force
  attempts. Guarantees here degrade exactly as far as the OS's own do (see Non-Goals).
- **Supply-chain attackers.** [ADR-0002](docs/adr/0002-zero-third-party-dependencies.md): the
  supply chain is Apple's SDKs, full stop. Doesn't cover a compromise of this repository's own
  history — see [SECURITY.md](SECURITY.md).
- **Misconfigured integrators** — not malicious, but a real actor: a misused API can produce a
  worse outcome than no framework. Mitigated by
  [Pillar 2](docs/APIDesignPhilosophy.md#pillar-2--hard-to-misuse-by-construction) — weakening a
  guarantee requires an API whose name says so.

## Explicit Non-Goals

If your risk model depends on any of these, this framework does not close that gap:

- **A fully compromised or jailbroken kernel.** Kernel-level access reads process memory,
  intercepts SE responses after the fact, and bypasses Data Protection outright — nothing in
  userspace can promise otherwise.
- **Protection after plaintext is intentionally exported.** `SecureBytes.dangerouslyExportBytes()`'s
  name is the entire warning; once bytes leave that way, their lifetime is the caller's problem.
  See [`SecureBytes`'s doc comment](Sources/BolourSecurityCore/Memory/SecureBytes.swift) for
  exactly what is and isn't zeroed.
- **Server compromise.** A compromised backend can mint valid-looking tokens or serve malicious
  pins; this framework defends the client, not your infrastructure.
- **Compromised signing identities.** A stolen signing certificate produces a binary Apple, App
  Attest, and this framework all treat as legitimate. Out of scope entirely.
- **Trust decisions this framework delegates.** Chain validation, hostname verification, and
  revocation checking are `SecTrust`'s — see
  [`BolourCertificates`'s Non-Goals](docs/modules/BolourCertificates.md#non-goals-explicit).

## Fail-Stop Policy

Every `precondition`/`try!`/force-cast in this codebase was read directly, not sampled. Each
falls into one of two categories; anything else is a bug:

1. **Programmer-error contract violations at API boundaries** — a negative byte count, an empty
   `AuthenticationReason` literal, a `VaultPath` starting with `/`. These are the caller's
   mistake at a call site they control (usually a literal), not attacker input. The fix is
   always "fix the calling code."
2. **Catastrophic, fail-stop infrastructure failure** — `SecureRandom`'s
   `precondition(status == errSecSuccess, ...)` guards `SecRandomCopyBytes` itself failing, the
   CSPRNG every nonce, key, and PKCE verifier depends on. A security framework that kept running
   after its randomness source failed would hand out predictable "random" values exactly when
   that's most dangerous. There's no recovery better than crashing.

The one `try!` (`SigningKey.software()`) is infallible by construction — no external input on
that path. The one force-cast (`SecureEnclaveKey.load(tag:)`) now sits behind an explicit
`CFGetTypeID` check rather than an unchecked assumption — see
[the API review notes](docs/APIDesignPhilosophy.md#the-api-review-checklist).

## Per-Module Threat Summary

| Module | Assets Protected | Attack Surface | Trust Assumptions | Failure Mode | Primary Mitigation |
|---|---|---|---|---|---|
| `BolourSecurityCore` | Secret bytes in memory, shared error/logging vocabulary | In-process memory only | The OS's own memory protections; ARC | A log call site leaking secret material | Redacting `description`; never `Codable` |
| `BolourKeychain` | Anything an app stores as a secret | Local — another process, or a stolen/locked device | Data Protection keychain's own guarantees | Wrong `ProtectionPolicy` chosen | Safe-by-default protection class; weakening needs a named parameter |
| `BolourBiometrics` | The access decision (biometry itself is Apple's) | Local — bypassing the prompt | `LAContext`'s own security model | A `Bool` result misread/inverted | Success returns a scoped `AuthenticatedContext`, never a `Bool` |
| `BolourCrypto` | Private/symmetric keys, randomness | In-process; SE's own boundary for `SecureEnclaveKey` | CryptoKit/Security.framework correctness (composed, never invented) | Silent SE→software fallback | `SecureEnclaveKey.create` throws instead of substituting ([ADR-0006](docs/adr/0006-secure-enclave-first-key-design.md)) |
| `BolourCertificates` | Certificate pins, parsed metadata | **Adversarial network input** — a malicious/MITM chain | `SecTrust` for all trust decisions | A malformed cert crashing/hanging the parser | Total, bounds-checked DER parsing (see the fuzz suite) |
| `BolourSecureStorage` | Encrypted files, token custody | Local — stolen/locked device, other local processes | The KDF key hierarchy; underlying Keychain/Crypto guarantees | Master key not yet SE-wrapped ([Known limitations](CHANGELOG.md#known-limitations)) | Per-file key derivation, sealed manifest, actor isolation |
| `BolourNetworkSecurity` | The TLS session itself | **Network attackers** — on-path, hostile Wi-Fi, DNS spoofing | System trust plus the pinning policy | An unpinned host accepting a valid-but-wrong cert | Fail-closed pinning; `UnvalidatedTrustOverride` self-logs unconditionally |
| `BolourJWT` | Bearer token integrity and claims | **Adversarial network input** — hostile/malformed tokens | The verifier's key set, never the token header | Algorithm confusion, `alg: none` | Allowlist from keys, not headers — [structurally unreachable](docs/modules/BolourJWT.md#architecture) |
| `BolourAppIntegrity` | Device/app legitimacy signals | Apple's App Attest/DeviceCheck; replay of stale assertions | Apple's attestation root; **server verification is mandatory** | Treating a local call as proof of anything | See [client-vs-server table](docs/modules/BolourAppIntegrity.md#what-the-client-can-prove-vs-what-only-the-server-can-decide) |
| `BolourOAuth` | Refresh tokens, the auth flow itself | **Network attackers**; a compromised authorization server | PKCE + `state`; the token endpoint's rotation/reuse behavior | Inconsistent token state under concurrent refresh | Actor-isolated single-flight refresh with rotation-aware poisoning, tested under 100-way bursts |

## Responsibilities Split

- **This framework:** safe-by-default primitives, honest failure semantics, an insecure path
  that's always visibly named.
- **The application:** choosing protection/pinning/validation policies for its actual threat
  model, server-side verification of anything this framework can only prove client-side (App
  Attest, bearer JWTs), and everything about its own server, signing identity, and logic.
- **The server:** what no client library can verify about itself — App Attest verification
  against Apple, JWT issuance/revocation, refresh-token rotation and reuse detection, and
  treating any client-supplied signal as evidence, not a verdict.
