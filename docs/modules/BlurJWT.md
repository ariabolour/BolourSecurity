# BlurJWT

**Layer 3 · Protocols & Services.** JOSE done the way the RFC authors wish everyone did it.

## Mission

Provide JWT creation and verification in which the historical vulnerability catalog — `alg: none`, algorithm confusion, unvalidated audiences, clock-skew abuse, unverified-claims access — is not "mitigated" but *unrepresentable*. Verification is typed: an `UnverifiedJWT` has no claims; only a `JWTVerifier` can produce a `VerifiedJWT<Claims>`, and it validates time, issuer, and audience by default.

## Responsibilities

- JWS: signing and verification (ES256, EdDSA, HS256 — the curated set; see Architecture for why RSA waits).
- Typed claims: standard registered claims plus app-defined `Codable` claims types.
- Validation policy: expiry/not-before with bounded leeway, mandatory issuer + audience, algorithm allowlisting bound to key type.
- JWK / JWK Set parsing, JWKS fetching with rotation-aware caching (`RemoteJWKSet`).
- Compact serialization parsing that is fuzz-hardened and allocation-bounded.

Out of scope: JWE (encrypted tokens — roadmap, gated on real demand), server-side issuance frameworks (we document interop; reference vectors ship in the repo).

## Public API (signature-level design)

```swift
// MARK: Parsing (no trust conferred)
public struct UnverifiedJWT: Sendable {
    public init(compactSerialization: String) throws(JWTError)   // structure-validated only
    public var unverifiedHeader: JWTHeader { get }                // name warns at every use
    // There is deliberately NO claims accessor here.
}

// MARK: Claims
public protocol JWTClaims: Codable, Sendable { }
public struct RegisteredClaims: JWTClaims {
    public var issuer: String?
    public var subject: String?
    public var audience: [String]?
    public var expiresAt: Date?
    public var notBefore: Date?
    public var issuedAt: Date?
    public var tokenID: String?
}

// MARK: Verification — the only door to claims
public struct JWTVerifier: Sendable {
    /// Keys carry their algorithm (phantom types from BlurCrypto), so the
    /// allowlist is derived from the keys — never from the token's header.
    public init(keys: some Collection<any JWTVerificationKey>,
                policy: JWTValidationPolicy)
    public init(jwks: some JWKSProviding,                        // RemoteJWKSet conforms
                policy: JWTValidationPolicy)

    public func verify<C: JWTClaims>(
        _ token: UnverifiedJWT, as _: C.Type = RegisteredClaims.self
    ) async throws(JWTError) -> VerifiedJWT<C>
}

public struct VerifiedJWT<Claims: JWTClaims>: Sendable {
    public var claims: Claims { get }
    public var registered: RegisteredClaims { get }
    public var verifiedAt: Date { get }
}

public struct JWTValidationPolicy: Sendable {
    /// Issuer and audience are REQUIRED init parameters — the two checks most
    /// verifiers skip are the two you cannot skip here.
    public init(issuer: String,
                audience: String,
                clockSkewTolerance: Duration = .seconds(60),     // capped: see below
                requireExpiry: Bool = true)
    // clockSkewTolerance is clamped to a documented maximum (5 minutes);
    // "disable time validation" has no spelling.
}

// MARK: Signing
public struct JWTSigner: Sendable {
    public init(key: SigningKey<P256>, keyID: String? = nil)     // ES256
    public init(key: SigningKey<Ed25519>, keyID: String? = nil)  // EdDSA
    public init(secureEnclaveKey: SecureEnclaveKey, keyID: String? = nil)
    public init(hmacKey: SymmetricKey, keyID: String? = nil)     // HS256; docs steer to asymmetric

    public func sign<C: JWTClaims>(_ claims: C,
                                   expiresIn: Duration) async throws(JWTError) -> SignedJWT
}
public struct SignedJWT: Sendable { public var compactSerialization: String { get } }

// MARK: JWKS
public protocol JWKSProviding: Sendable {
    func currentKeys() async throws -> [any JWTVerificationKey]
}
public actor RemoteJWKSet: JWKSProviding {
    /// Fetches over the caller's (ideally pinned) session; caches per Cache-Control;
    /// on kid-miss performs one bounded refresh (rotation), then fails — no refresh stampede.
    public init(url: URL, session: URLSession = .shared,
                cachePolicy: JWKSCachePolicy = .default)
}

public enum JWTError: SecurityError {
    case malformedToken(detail: MalformationDetail)
    case signatureInvalid
    case algorithmMismatch(tokenAlgorithm: String)   // header claimed something our keys aren't
    case expired(at: Date)
    case notYetValid(until: Date)
    case issuerMismatch(expected: String)            // token's value intentionally omitted from description
    case audienceMismatch(expected: String)
    case unknownKeyID(String)
    case claimsDecodingFailed(underlying: any Error & Sendable)
    case jwksUnavailable(underlying: any Error & Sendable)
}
```

## Dependencies

`BlurSecurityCore`, `BlurCrypto`; Apple: Foundation. (`RemoteJWKSet` accepts a `URLSession` — apps pass a `BlurNetworkSecurity` pinned session; the module itself stays off the network by default.)

## Architecture

- **The header never chooses the algorithm.** The verifier's key set determines acceptable algorithms; the token's `alg` is checked for *consistency* and otherwise ignored. `none` is not an enum case anywhere in the module. This kills both `alg: none` and RS256→HS256 confusion by construction — which is also why RSA support waits: shipping RSA re-opens the confusion surface and CryptoKit doesn't provide it natively (Security.framework does); it arrives only with its own ADR (roadmap).
- Compact-serialization parsing is allocation-bounded (segment count and size limits before base64 decode) — hostile tokens from the network are the assumed input.
- Claims dates use `NumericDate` per RFC 7519 with explicit sub-second truncation rules; encoding is bit-stable across releases (golden files).
- `RemoteJWSet`'s single-flight refresh is one of the reasons it's an actor; verification itself is pure and value-typed.

## Usage Examples

```swift
import BlurJWT

struct SessionClaims: JWTClaims { let userID: String; let roles: [String] }

let verifier = JWTVerifier(
    jwks: RemoteJWKSet(url: jwksURL, session: pinnedSession),
    policy: JWTValidationPolicy(issuer: "https://auth.example.com",
                                audience: "com.example.app")
)
let verified = try await verifier.verify(UnverifiedJWT(compactSerialization: raw),
                                         as: SessionClaims.self)
let userID = verified.claims.userID          // claims exist only after verification

// Device-bound proof-of-possession token
let signer = JWTSigner(secureEnclaveKey: deviceKey, keyID: "device-2026")
let jwt = try await signer.sign(SessionClaims(userID: id, roles: []), expiresIn: .seconds(300))
```

## Testing Strategy

- **RFC vectors:** RFC 7515/7519/8037 test vectors as golden tests; interop fixtures generated by mainstream issuers (a checked-in corpus of tokens minted by common IdPs' formats).
- **Attack corpus as permanent regression suite:** `alg: none` variants, algorithm-confusion tokens, empty/duplicated segments, oversized headers, unicode/base64url edge cases, embedded-JWK (CVE-pattern) headers, `kid` injection strings — every one must fail with the *specific* typed error asserted.
- Fuzzing of compact-serialization parsing (crash-free + bounded-allocation invariants), shared harness with BlurCertificates' DER fuzzer.
- Time-validation property tests across skew/leeway boundaries with injected clocks.
- `RemoteJWKSet`: rotation single-flight (N concurrent kid-misses ⇒ 1 fetch), cache-policy honor, offline behavior.

## Security Considerations & Common Mistakes Prevented

- **Prevented: `alg: none` and algorithm confusion** — unrepresentable (see Architecture).
- **Prevented: reading claims before verification** — `UnverifiedJWT` has no claims accessor; code review sees `unverifiedHeader` when someone routes around intent.
- **Prevented: skipped issuer/audience checks** — required constructor parameters.
- **Prevented: unbounded clock-skew "fixes"** — leeway is clamped; the temptation to widen it to paper over server clock drift hits a documented wall with the correct remedy named (fix the clock).
- **Prevented: JWKS refresh stampedes and rotation races** — single-flight actor semantics.
- **Honest limits:** JWTs are bearer tokens; possession is authority. The security-considerations article covers storage (use `TokenStore`), transport (pinned sessions), lifetime discipline, and when *not* to use JWTs (session tokens that need revocation).

## Future Roadmap

- RS256/PS256 via Security.framework, behind its own ADR and confusion-surface analysis (v2.0 — enterprise IdP reality).
- JWE (encrypted payloads) (v2.x, demand-gated).
- DPoP proof generation (pairs with the SecureEnclaveKey signer) (v2.x, with BlurOAuth).
- `swift-jose` ecosystem watch: if Apple ships first-party JOSE, we adapt per Manifesto Law 7.
