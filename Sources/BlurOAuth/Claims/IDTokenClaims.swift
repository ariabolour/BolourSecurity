import BlurJWT

/// The OIDC ID token claims this module reads. App-specific claims can be read via a custom
/// `JWTClaims` type passed directly to `BlurJWT.JWTVerifier` if needed beyond sign-in.
public struct IDTokenClaims: JWTClaims {
    public let subject: String?
    public let email: String?
    public let name: String?
    let nonce: String?

    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case email
        case name
        case nonce
    }
}
