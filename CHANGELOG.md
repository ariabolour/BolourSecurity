# Changelog

All notable changes to BlurSecurity are documented here, per [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with the discipline defined in [ReleaseStrategy §5](docs/ReleaseStrategy.md): entries are written with the change that makes them true, and the `Security` section is never omitted (releases with no security changes say so).

## [Unreleased]

### Security
- Nothing yet since 1.0.0.

## [1.0.0] - 2026-08-15

The first code release: all ten modules plus the umbrella package, built module-by-module from the architecture recorded in `docs/`.

### Added
- **BlurSecurityCore** — shared vocabulary: `SecureBytes`, `ProtectionPolicy`/`PresenceRequirement`, typed `SecurityError`, redacting `SecurityEventLogger`, and the Core protocol seams (`SecretStore`, `TrustEvaluating`, `AttestationProviding`, `PresenceAuthenticated`) that keep every higher module independently importable.
- **BlurCrypto** — hashing (SHA-2, streaming file digests), HMAC, AES-256-GCM/ChaCha20-Poly1305 sealing via a versioned envelope, software P-256/Ed25519 signing, HKDF/PBKDF2 key derivation, `SecureRandom`, and Secure Enclave-backed P-256 signing keys (`SecureEnclaveKey`) per [ADR-0006](docs/adr/0006-secure-enclave-first-key-design.md).
- **BlurKeychain** — a typed, async, value-semantic front end to the Data Protection keychain; `@KeychainStored` and `SecretStore` conformance.
- **BlurCertificates** — an in-tree, fuzz-hardened X.509/DER parser for introspection, `SecTrust`-backed trust evaluation, and SPKI pinning whose shape makes a single-pin policy a compile error.
- **BlurNetworkSecurity** — `URLSession.secure(policy:)` and `SecureSessionDelegate`: fail-closed certificate pinning and a TLS floor enforced structurally, with a self-indicting local-development override.
- **BlurBiometrics** — `BiometricAuthenticator`: Face ID/Touch ID/Optic ID/passcode behind one policy API, producing the `AuthenticatedContext` that closes the `PresenceAuthenticated` seam.
- **BlurSecureStorage** — `Vault` (an encrypted, actor-isolated file container with a KDF-derived per-file key hierarchy and a sealed manifest) and `TokenStore` (the canonical `SecretStore` conformer with expiry semantics).
- **BlurAppIntegrity** — `AttestationService`: the full App Attest lifecycle (key generation, attestation, assertions, invalidation recovery) as a state machine, plus `DeviceCheckToken`.
- **BlurJWT** — JWS signing/verification (ES256, EdDSA, HS256) where algorithm confusion and `alg: none` are unrepresentable by construction, plus JWK/JWKS parsing with a caching, single-flight `RemoteJWKSet`.
- **BlurOAuth** — Authorization Code + PKCE via `ASWebAuthenticationSession`, OIDC discovery and ID-token verification, and `TokenManager`'s single-flight, rotation-aware token refresh.
- **BlurSecurity** — the umbrella product re-exporting all ten modules behind one `import`.
- Apache-2.0 `LICENSE`, per [ADR-0007](docs/adr/0007-apache-2.0-license.md).
- `pr.yml`: a build matrix across macOS/iOS/watchOS/visionOS simulators, `swift test`, an informational coverage report, and the zero-third-party-dependency guard.

### Security
- Every module's typed error domain follows the `SecurityError` redaction contract: no case may carry key material, plaintext, tokens, or credentials in its description.
- Certificate pinning (`BlurCertificates`, `BlurNetworkSecurity`) is additive over system trust, never a replacement for it, and fails closed on an expired pin set rather than silently downgrading to unpinned.
- `BlurJWT`'s verifier derives its acceptable-algorithm allowlist from its own key set, never from a token's header — the standard mechanism for `alg: none` and algorithm-confusion attacks has no code path to reach.
- `BlurOAuth` has no `clientSecret` parameter on its public-client configuration, and PKCE/`state` are generated internally per attempt with no API to disable, downgrade, or override either.
- `SecureEnclaveKey` creation never silently falls back to a software key on hardware without a Secure Enclave; it throws a typed, distinctly-named error so the fallback is always a visible call-site decision.

### Known limitations
Recorded here rather than left implicit, matching every module's own "Honest limits" documentation:
- `BlurSecureStorage.Vault`'s master key is software-held, not yet Secure-Enclave-wrapped; `writeStream`/`readStream` buffer their full payload rather than encrypting in constant-memory segments.
- `BlurNetworkSecurity`'s JWKS/TLS-floor enforcement and `BlurJWT.RemoteJWKSet`'s caching are TTL-based, not full `Cache-Control`-header-aware.
- Real device/hardware round-trips (live Keychain access-group items, Secure Enclave key creation, biometric prompts, App Attest, `ASWebAuthenticationSession`) are unit-tested against scripted seams throughout, but are device/entitlement-gated for real execution — there is no CI lane that runs them yet (`nightly.yml`, a device-farm runner, and an app-hosted test target are all still outstanding).
- DocC ships only a landing page today, not the full per-module reference site or the "Store Your First Secret" tutorial; there is no published documentation site yet.
- No independent security audit has been performed.
