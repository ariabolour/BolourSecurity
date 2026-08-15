import Foundation
import BolourCrypto

/// Signs claims into a compact-serialization JWT.
public struct JWTSigner: Sendable {
    private let implementation: any JWTSigningImplementation
    private let keyID: String?

    public init(key: SigningKey<P256>, keyID: String? = nil) {
        self.implementation = ES256SigningImplementation(key: key)
        self.keyID = keyID
    }

    public init(key: SigningKey<Ed25519>, keyID: String? = nil) {
        self.implementation = EdDSASigningImplementation(key: key)
        self.keyID = keyID
    }

    public init(secureEnclaveKey: SecureEnclaveKey, keyID: String? = nil) {
        self.implementation = SecureEnclaveSigningImplementation(key: secureEnclaveKey)
        self.keyID = keyID
    }

    /// HS256. Docs steer toward the asymmetric initializers: the verifying party never needs
    /// signing-capable material with those, only with HMAC.
    public init(hmacKey: SymmetricKey, keyID: String? = nil) {
        self.implementation = HS256SigningImplementation(key: hmacKey)
        self.keyID = keyID
    }

    /// Signs `claims`, setting `iat` to now and `exp` to `now + expiresIn` — both truncated to
    /// whole seconds, matching RFC 7519 `NumericDate` as this ecosystem produces it.
    public func sign<C: JWTClaims>(_ claims: C, expiresIn: Duration) async throws(JWTError) -> SignedJWT {
        let header = JWTHeader(algorithm: implementation.jwtAlgorithm, keyID: keyID, type: "JWT")
        let encoder = ClaimsCoding.makeEncoder()

        let headerData: Data
        let payloadData: Data
        do {
            headerData = try encoder.encode(header)
            payloadData = try encoder.encode(SigningPayload(claims: claims, issuedAt: Date().truncatedToSeconds, expiresAt: Date().truncatedToSeconds.addingTimeInterval(expiresIn.timeInterval)))
        } catch {
            throw JWTError.signingFailed(underlying: error)
        }

        let headerSegment = Base64URL.encode(headerData)
        let payloadSegment = Base64URL.encode(payloadData)
        let signingInput = Data((headerSegment + "." + payloadSegment).utf8)
        let signature = try implementation.sign(signingInput)

        let compact = headerSegment + "." + payloadSegment + "." + Base64URL.encode(signature)
        return SignedJWT(compactSerialization: compact)
    }
}

/// Merges an arbitrary claims payload with the two registered claims `sign` itself sets
/// (`iat`/`exp`), by encoding both into one JSON object. `C` may itself declare `iat`/`exp` —
/// theirs lose, since the signer's own timestamps are the ones the signature actually reflects.
private struct SigningPayload<C: JWTClaims>: Encodable {
    let claims: C
    let issuedAt: Date
    let expiresAt: Date

    func encode(to encoder: Encoder) throws {
        try claims.encode(to: encoder)
        var container = encoder.container(keyedBy: RegisteredClaims.CodingKeys.self)
        try container.encode(issuedAt, forKey: .issuedAt)
        try container.encode(expiresAt, forKey: .expiresAt)
    }
}
