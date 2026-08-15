# BolourCrypto

**Layer 1 · Primitives.** Cryptography with CryptoKit's engine and BolourSecurity's guardrails.

## Mission

Make every common cryptographic operation — hashing, authenticated encryption, signing, key agreement, key derivation, randomness — a one-line call whose default parameters a cryptographer would have chosen, with hardware-backed keys as the flagship ([ADR-0006](../adr/0006-secure-enclave-first-key-design.md)). BolourCrypto invents no cryptography ever (Manifesto, Law 7); it curates CryptoKit, Security.framework, and CommonCrypto behind one coherent, misuse-resistant surface. This module also owns signing and verification — there is no separate signing module ([ADR-0005](../adr/0005-consolidated-module-set.md)).

## Responsibilities

- Hashing (SHA-2 family) including async streaming for large files.
- Authenticated symmetric encryption (AES-256-GCM default; ChaCha20-Poly1305 option). Unauthenticated modes do not exist in the public surface.
- Digital signatures: P-256, Ed25519 — software and Secure Enclave.
- Key agreement (ECDH) with HKDF-derived session keys.
- Key derivation: HKDF; PBKDF2 for password-derived keys (via CommonCrypto — Apple SDK, per [ADR-0002](../adr/0002-zero-third-party-dependencies.md)).
- Secure randomness.
- Secure Enclave key lifecycle: creation, persistence (as keychain-held handles), presence-gated use.

## Public API (signature-level design)

```swift
// MARK: Hashing
public enum SHA256 {
    public static func digest(of data: some DataProtocol) -> Digest256
    public static func digest(ofFileAt url: URL) async throws(CryptoError) -> Digest256  // streaming
}
public struct Digest256: Sendable, Hashable, ContiguousBytes { … }   // SHA384/512 analogous
public struct HMAC<H: BolourHashFunction> {
    public static func code(for data: some DataProtocol, using key: SymmetricKey) -> AuthenticationCode
    public static func isValidCode(_ code: AuthenticationCode,
                                   for data: some DataProtocol,
                                   using key: SymmetricKey) -> Bool    // constant-time
}

// MARK: Symmetric encryption (authenticated only)
public struct SymmetricKey: Sendable {
    public static func random(_ suite: CipherSuite = .aes256GCM) -> SymmetricKey
    public init(secureBytes: SecureBytes, suite: CipherSuite = .aes256GCM) throws(CryptoError)

    public func seal(_ plaintext: some DataProtocol,
                     authenticating aad: (some DataProtocol)? = nil)
        throws(CryptoError) -> SealedMessage                 // fresh random nonce, always
    public func open(_ message: SealedMessage,
                     authenticating aad: (some DataProtocol)? = nil)
        throws(CryptoError) -> Data
}
public enum CipherSuite: Sendable { case aes256GCM, chaChaPoly }
public struct SealedMessage: Sendable, Codable {             // nonce ‖ ciphertext ‖ tag, versioned
    public var combinedRepresentation: Data { get }
    public init(combinedRepresentation: Data) throws(CryptoError)
}
// Note: no public Nonce parameter exists on seal(). Nonce reuse — the classic
// catastrophic GCM failure — is unrepresentable, not merely discouraged.

// MARK: Signing (phantom-typed; a P256 signature can't meet an Ed25519 key)
public protocol SignatureAlgorithm: Sendable { }             // P256, Ed25519 conform
public struct SigningKey<A: SignatureAlgorithm>: Sendable {
    public static func software() -> SigningKey              // 'software' is the visible choice
    public var verificationKey: VerificationKey<A> { get }
    public func signature(for data: some DataProtocol) throws(CryptoError) -> Signature<A>
}
public struct VerificationKey<A: SignatureAlgorithm>: Sendable, Codable {
    public func isValidSignature(_ signature: Signature<A>, for data: some DataProtocol) -> Bool
}
public struct Signature<A: SignatureAlgorithm>: Sendable, Codable { … }

// MARK: Secure Enclave (the flagship key type)
public struct SecureEnclaveKey: Sendable {
    /// Creates a new P-256 key inside the Secure Enclave. Throws
    /// `.secureEnclaveUnavailable` on unsupported hardware — never silently
    /// falls back to a software key (ADR-0006).
    public static func create(
        tag: ItemKey,
        presence: PresenceRequirement = .none,
        protection: ProtectionPolicy = .default
    ) throws(CryptoError) -> SecureEnclaveKey

    public static func load(tag: ItemKey) throws(CryptoError) -> SecureEnclaveKey?
    public static func destroy(tag: ItemKey) throws(CryptoError)

    public var verificationKey: VerificationKey<P256> { get }
    /// async: may present a biometric prompt when created with a presence requirement.
    public func signature(for data: some DataProtocol,
                          context: AuthenticatedContext? = nil) async throws(CryptoError) -> Signature<P256>
    public func sharedSecret(with peer: VerificationKey<P256>,
                             context: AuthenticatedContext? = nil) async throws(CryptoError) -> SharedSecret
}

// MARK: Key agreement & derivation
public struct SharedSecret: Sendable {
    public func sessionKey(info: some DataProtocol,
                           salt: (some DataProtocol)? = nil,
                           suite: CipherSuite = .aes256GCM) -> SymmetricKey   // HKDF-SHA256
}
public enum KeyDerivation {
    public static func hkdf(from secret: SecureBytes, salt: some DataProtocol,
                            info: some DataProtocol, outputByteCount: Int) -> SecureBytes
    /// PBKDF2-HMAC-SHA256. Iteration default reviewed each release; floor enforced.
    public static func fromPassword(_ password: String, salt: some DataProtocol,
                                    parameters: PasswordHashingParameters = .default)
        throws(CryptoError) -> SecureBytes
}

// MARK: Randomness
public enum SecureRandom {
    public static func bytes(count: Int) -> SecureBytes
    public static func data(count: Int) -> Data
    public static func number<T: FixedWidthInteger>(in range: Range<T>) -> T   // rejection-sampled, unbiased
}
```

## Dependencies

`BolourSecurityCore`; Apple: CryptoKit, Security, CommonCrypto, Foundation.

## Architecture

- Thin, total mappings onto CryptoKit types internally (`SymmetricKey` wraps `CryptoKit.SymmetricKey`; `SigningKey<P256>` wraps `P256.Signing.PrivateKey`; `SecureEnclaveKey` wraps `SecureEnclave.P256` with keychain-persisted handles shared with BolourKeychain via an internal Core seam).
- `SealedMessage.combinedRepresentation` carries a 1-byte format version so future suite migrations decode old ciphertexts unambiguously.
- All comparisons of secret material (HMAC verification, digest equality where secret-adjacent) route through constant-time comparison; `==` on secret types is documented as constant-time.
- `AuthenticatedContext` (from BolourBiometrics) is *accepted* here via a Core seam protocol so BolourCrypto never imports upward — the parameter is typed as `some PresenceAuthenticated` defined in Core (naming refined during implementation; the layering rule is the invariant).

## Usage Examples

```swift
import BolourCrypto

// Encrypt-then-store in three honest lines
let key = SymmetricKey.random()
let sealed = try key.seal(documentData)
let restored = try key.open(sealed)

// Hardware-backed request signing, biometry-gated
let deviceKey = try SecureEnclaveKey.create(tag: .requestSigning, presence: .biometry())
let signature = try await deviceKey.signature(for: requestDigest)
```

## Testing Strategy

- **Known-answer tests** from NIST CAVP vectors (AES-GCM, SHA-2, HMAC, HKDF, PBKDF2) and RFC test vectors (Ed25519: RFC 8032; ChaCha20-Poly1305: RFC 8439).
- Round-trip and tamper tests: every `seal` output must fail `open` under any single-bit flip (ciphertext, tag, nonce, AAD).
- `SealedMessage` decode fuzzing (malformed/truncated/version-skewed inputs never crash, always throw typed errors).
- Secure Enclave suites run on device CI and are tagged `.requiresDevice`; simulator CI covers software paths and the `.secureEnclaveUnavailable` throw.
- Statistical smoke tests on `SecureRandom.number(in:)` bias (chi-squared over large samples, generous tolerance — a regression tripwire, not a randomness proof).
- Benchmarks: seal/open throughput across payload sizes, SE signature latency, PBKDF2 calibration.

## Security Considerations & Common Mistakes Prevented

- **Prevented: nonce reuse under GCM** — no API accepts a caller-provided nonce.
- **Prevented: unauthenticated encryption** — CBC/CTR/ECB have no public spelling.
- **Prevented: algorithm confusion** — phantom types bind signatures to algorithms at compile time.
- **Prevented: silent hardware downgrade** — SE unavailability throws; `software()` is a visible, greppable decision (ADR-0006).
- **Prevented: modulo-biased "random" numbers** — `SecureRandom.number(in:)` is rejection-sampled.
- **Honest limits:** PBKDF2 is the strongest password KDF in Apple's SDKs; we document that memory-hard KDFs (Argon2, scrypt) are unavailable without third-party code, which ADR-0002 forbids — apps with that requirement should keep password hashing server-side.

## Future Roadmap

- ECIES-style one-shot sealed boxes to a `VerificationKey` recipient (v0.5).
- Key-wrapping conveniences (AES-KW) for vault master keys (v0.5, with BolourSecureStorage).
- Adopt post-quantum primitives the moment CryptoKit ships them, behind the same API shapes (tracked; version depends on Apple).
- `@_spi(Experimental)` envelope-encryption helpers for multi-recipient documents (v2.x).
