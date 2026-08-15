import BolourJWT

/// A live, signed-in session.
public struct OAuthSession: Sendable {
    /// Present iff the configuration was OIDC (`.discovering(...)`) and ID-token verification
    /// succeeded.
    public let user: VerifiedJWT<IDTokenClaims>?
    public let tokens: TokenManager
}
