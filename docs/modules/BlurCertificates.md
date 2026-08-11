# BlurCertificates

**Layer 2 · Capabilities.** X.509 made legible; trust made explicit; pinning made hard to get wrong.

## Mission

Give developers a typed view of certificates and chains, a trust evaluator with honest semantics, and a pinning policy whose *shape* enforces operational best practice (SPKI pins, mandatory backup pins) — so that the difference between "TLS" and "TLS to the party I meant" becomes a value the app declares and tests. `BlurNetworkSecurity` consumes this module's policies; this module owns their meaning.

## Responsibilities

- Parsing DER/PEM certificates into a typed `Certificate` (the fields that matter for validation and pinning: subject, issuer, validity, SPKI, SANs, key usage, basic constraints). Minimal in-tree DER parsing per [ADR-0002](../adr/0002-zero-third-party-dependencies.md) — we parse what we validate, nothing more.
- Chain evaluation via `SecTrust` with typed outcomes (`EvaluatedCertificateChain`).
- `PinningPolicy`: SPKI-hash pinning with structurally mandatory backup pins, per-host scoping, and explicit expiry behavior.
- SPKI hash computation and tooling-friendly export (so ops teams can generate pins from `openssl` output or from a `Certificate`).
- The `TrustEvaluating` conformance consumed through the Core seam.

## Public API (signature-level design)

```swift
public struct Certificate: Sendable, Hashable {
    public init(derEncoded: Data) throws(CertificateError)
    public init(pemEncoded: String) throws(CertificateError)

    public var subject: DistinguishedName { get }
    public var issuer: DistinguishedName { get }
    public var validity: ClosedRange<Date> { get }
    public var subjectAlternativeNames: [SubjectAlternativeName] { get }
    public var publicKeyInfo: SubjectPublicKeyInfo { get }
    public var isCertificateAuthority: Bool { get }
    public var derRepresentation: Data { get }
}

public struct SPKIHash: Sendable, Hashable, Codable {
    /// SHA-256 of the DER-encoded SubjectPublicKeyInfo — the HPKP/industry convention.
    public init(of certificate: Certificate)
    public init(base64Encoded: String) throws(CertificateError)
    public var base64EncodedString: String { get }
}

public struct PinningPolicy: Sendable, Hashable {
    /// Backup pins are structurally mandatory: a policy with a single pin cannot
    /// be constructed. (Pinning without a backup is how apps brick themselves.)
    public init(
        host: PinnedHost,
        primary: SPKIHash,
        backups: NonEmptyPins,                     // ≥ 1 by type
        includeSubdomains: Bool = false,
        expiry: PinExpiryBehavior = .enforceUntil(nil)
    )
}
public struct NonEmptyPins: Sendable, Hashable {
    public init(_ first: SPKIHash, _ rest: SPKIHash...)
}
public enum PinExpiryBehavior: Sendable, Hashable {
    /// Pins enforced until the given date; after it, evaluation fails CLOSED with
    /// `.pinSetExpired` — a loud, typed failure telling ops to ship rotated pins,
    /// never a silent downgrade to unpinned TLS. `nil` = no expiry.
    case enforceUntil(Date?)
}

public struct TrustEvaluator: TrustEvaluating, Sendable {
    public init(pinning: [PinningPolicy] = [],
                logger: (any SecurityEventLogger)? = nil)

    /// System trust ALWAYS evaluates first; pins are enforced in addition, never instead.
    public func evaluate(_ chain: CertificateChain,
                         for host: String) async throws(CertificateError) -> EvaluatedCertificateChain
}

/// Proof of evaluation — the only chain type BlurNetworkSecurity accepts as trusted.
public struct EvaluatedCertificateChain: Sendable {
    public var leaf: Certificate { get }
    public var host: String { get }
    public var evaluatedAt: Date { get }
    public var matchedPin: SPKIHash? { get }
}

public enum CertificateError: SecurityError {
    case malformedEncoding(detail: MalformationDetail)
    case systemTrustFailed(underlying: OSStatus, host: String)
    case hostnameMismatch(host: String, presented: [SubjectAlternativeName])
    case expired(notAfter: Date)
    case notYetValid(notBefore: Date)
    case pinMismatch(host: String)                  // deliberately omits presented hashes: see below
    case pinSetExpired(host: String, expiredAt: Date)
    case revocationCheckFailed(host: String)
}
```

## Dependencies

`BlurSecurityCore`, `BlurCrypto` (SPKI hashing); Apple: Security (`SecTrust`, `SecCertificate`), Foundation.

## Architecture

- **Two engines, one truth.** Chain *evaluation* delegates to `SecTrust` (Apple's evaluator, revocation, CT — we never reimplement path validation). Certificate *parsing* is our minimal DER reader, used for introspection and SPKI extraction only — never as a trust decision engine. The boundary is a module-internal rule checked in review: no parsing result influences `evaluate` beyond pin comparison.
- The DER reader is a non-allocating cursor over `[UInt8]` handling exactly: SEQUENCE/SET, INTEGER, OID, BIT STRING, OCTET STRING, UTCTime/GeneralizedTime, UTF8/Printable/IA5 strings, and the extensions we surface. Unknown critical extensions ⇒ `malformedEncoding` on parse-for-validation paths (honest refusal beats silent ignorance).
- `pinMismatch` deliberately does **not** include the presented certificate's hashes in the error (an active MITM shouldn't get free confirmation of what the app expected vs. saw in logs that apps often upload); full detail is available through the structured `SecurityEvent` channel, which apps control.

## Usage Examples

```swift
import BlurCertificates

let apiPins = PinningPolicy(
    host: "api.example.com",
    primary: SPKIHash(base64Encoded: "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="),
    backups: NonEmptyPins(SPKIHash(base64Encoded: "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")),
    expiry: .enforceUntil(certRotationDeadline)
)

let evaluator = TrustEvaluator(pinning: [apiPins])
let evaluated = try await evaluator.evaluate(presentedChain, for: "api.example.com")
```

## Testing Strategy

- **Parser fuzzing is the headline investment:** corpus-driven fuzzing of the DER reader (truncations, length-field lies, nesting bombs, indefinite lengths, oversized OIDs) with an explicit crash-free + typed-error invariant. Fuzz corpus checked into the repo; CI runs a bounded pass per PR and a long pass nightly.
- Known-certificate tests: real-world cert fixtures (Let's Encrypt chains, cross-signed chains, name-constrained CAs, expired/not-yet-valid, IP SANs, wildcard SANs) with snapshot-asserted parse results.
- `SecTrust` integration tests with generated test CAs (fixtures created by a checked-in generation script): valid chain, wrong host, expired leaf, untrusted root, and the pin matrix (primary hit, backup hit, miss, expiry behavior).
- Property test: `SPKIHash(of:)` equals `openssl`-derived reference hashes for the fixture corpus.

## Security Considerations & Common Mistakes Prevented

- **Prevented: pinning without a backup** — unconstructible (`NonEmptyPins`), converting the industry's most common self-inflicted outage into a compile error.
- **Prevented: pinning *instead of* trust** — pins are additive over system trust by construction; a pinned-but-invalid chain always fails.
- **Prevented: silent pin expiry downgrade** — expiry fails closed with a distinct, alertable error.
- **Prevented: certificate pins (vs. SPKI pins)** — leaf-certificate pinning breaks on every renewal; our policy type only speaks SPKI, which survives key-preserving renewals.
- **Prevented: home-rolled hostname matching** — hostname verification is `SecTrust`'s, not ours.
- **Honest limits:** pinning is a mitigation against misissuance and interception, and a *commitment* with operational cost; the DocC article "Should You Pin?" gives regulated-industry guidance including the case for *not* pinning (short-lived certs + CT monitoring), because honest guidance is part of the API.

## Future Roadmap

- Identity (`SecIdentity`) import/export and client-certificate support (v2.0, with BlurNetworkSecurity mTLS).
- OCSP-stapling introspection surfacing (v2.x, as `SecTrust` exposes allow).
- Pin-generation command-line helper under `Examples/` tooling (v1.0 — adoption-critical for ops teams).
- Certificate Transparency policy surfacing (`requireCT`) (v2.x).
