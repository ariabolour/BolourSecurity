import Foundation

/// Where an `OAuthClient`'s endpoints come from: OIDC discovery, resolved lazily and cached for
/// the client's lifetime, or fixed endpoints supplied directly for non-OIDC providers.
///
/// Both entry points **throw**: every URL is validated here, at the earliest possible moment,
/// rather than at the first network call that would have leaked something. See
/// ``EndpointValidation`` for the rules and ``MisconfigurationDetail`` for what a rejection says.
/// Endpoints that arrive later from OIDC discovery are validated again on the way in — a
/// configuration-time check cannot vouch for a document fetched afterwards.
public struct OAuthConfiguration: Sendable {
    enum EndpointSource: Sendable {
        case explicit(authorization: URL, token: URL, revocation: URL?)
        case discovering(issuer: URL)
    }

    let endpointSource: EndpointSource
    let clientID: String
    let redirectURI: URL
    let scopes: ScopeSet
    /// Whether ID-token verification applies — true only for `.discovering` (OIDC) configuration.
    let isOIDC: Bool

    /// OIDC discovery: endpoints are fetched from the issuer's `.well-known/openid-configuration`
    /// and validated (§Architecture: token/authorization endpoints must share the issuer's host —
    /// mix-up-attack hygiene) the first time they're needed, then pinned for the client's lifetime.
    public static func discovering(
        issuer: URL, clientID: String, redirectURI: URL, scopes: ScopeSet
    ) throws(OAuthError) -> OAuthConfiguration {
        try EndpointValidation.validateIssuer(issuer)
        try EndpointValidation.validateRedirectURI(redirectURI)
        return OAuthConfiguration(
            endpointSource: .discovering(issuer: issuer), clientID: clientID,
            redirectURI: redirectURI, scopes: scopes, isOIDC: true
        )
    }

    /// Explicit endpoints for non-OIDC providers. No `clientSecret` parameter exists here on
    /// purpose: secrets embedded in a distributed app binary are not a thing this module helps
    /// anyone do. Server-mediated confidential-client flows are a documented pattern, not an API.
    public init(
        authorizationEndpoint: URL, tokenEndpoint: URL,
        clientID: String, redirectURI: URL, scopes: ScopeSet, revocationEndpoint: URL? = nil
    ) throws(OAuthError) {
        try EndpointValidation.validateServerEndpoint(authorizationEndpoint, as: .authorization)
        try EndpointValidation.validateServerEndpoint(tokenEndpoint, as: .token)
        if let revocationEndpoint {
            try EndpointValidation.validateServerEndpoint(revocationEndpoint, as: .revocation)
        }
        try EndpointValidation.validateRedirectURI(redirectURI)
        self.init(
            endpointSource: .explicit(authorization: authorizationEndpoint, token: tokenEndpoint, revocation: revocationEndpoint),
            clientID: clientID, redirectURI: redirectURI, scopes: scopes, isOIDC: false
        )
    }

    private init(endpointSource: EndpointSource, clientID: String, redirectURI: URL, scopes: ScopeSet, isOIDC: Bool) {
        self.endpointSource = endpointSource
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.isOIDC = isOIDC
    }
}
