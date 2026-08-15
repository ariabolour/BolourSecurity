import Foundation

/// Proof that a token's signature, expiry, issuer, and audience all checked out — the only way
/// to reach a token's claims. `JWTVerifier.verify(_:as:)` is the only initializer.
public struct VerifiedJWT<Claims: JWTClaims>: Sendable {
    public let claims: Claims
    public let registered: RegisteredClaims
    public let verifiedAt: Date

    init(claims: Claims, registered: RegisteredClaims, verifiedAt: Date) {
        self.claims = claims
        self.registered = registered
        self.verifiedAt = verifiedAt
    }
}
