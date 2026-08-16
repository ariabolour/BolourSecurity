import Foundation

/// The endpoints an `OAuthClient` actually uses for one configuration — either passed in
/// directly or resolved once via OIDC discovery and cached.
struct ResolvedEndpoints: Sendable {
    let authorization: URL
    let token: URL
    let revocation: URL?
    let jwksURI: URL?
}

struct OIDCDiscoveryDocument: Decodable {
    let issuer: String
    let authorizationEndpoint: String
    let tokenEndpoint: String
    let revocationEndpoint: String?
    let jwksURI: String?

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case jwksURI = "jwks_uri"
    }
}

extension OAuthConfiguration {
    func resolveEndpoints(session: URLSession) async throws(OAuthError) -> ResolvedEndpoints {
        switch endpointSource {
        case .explicit(let authorization, let token, let revocation):
            return ResolvedEndpoints(authorization: authorization, token: token, revocation: revocation, jwksURI: nil)

        case .discovering(let issuer):
            let wellKnown = issuer.appendingPathComponent(".well-known").appendingPathComponent("openid-configuration")
            let data: Data
            do {
                (data, _) = try await session.data(from: wellKnown)
            } catch {
                throw OAuthError.discoveryFailed(issuer: issuer, underlying: error)
            }

            let document: OIDCDiscoveryDocument
            do {
                document = try JSONDecoder().decode(OIDCDiscoveryDocument.self, from: data)
            } catch {
                throw OAuthError.discoveryFailed(issuer: issuer, underlying: error)
            }

            // RFC 8414 §3.3: the document's own `issuer` must match the one that was queried.
            // Previously decoded and never checked — a provider that disagrees with itself about
            // its identity is one someone else may be speaking for.
            guard document.issuer == issuer.absoluteString else {
                throw OAuthError.providerMisconfigured(detail: .discoveredIssuerMismatch(expected: issuer))
            }

            guard let authorizationURL = URL(string: document.authorizationEndpoint),
                  let tokenURL = URL(string: document.tokenEndpoint)
            else {
                throw OAuthError.providerMisconfigured(detail: .incompleteDiscoveryDocument)
            }
            // Discovery metadata is a network document naming *other* URLs. Configuration-time
            // validation says nothing about it, so every endpoint it hands back is validated
            // here too — a `http://` token endpoint would carry the authorization code and the
            // tokens it buys in cleartext.
            try EndpointValidation.validateServerEndpoint(authorizationURL, as: .authorization)
            try EndpointValidation.validateServerEndpoint(tokenURL, as: .token)

            // Mix-up-attack hygiene: discovery metadata is never trusted to redirect the token
            // exchange to a different host than the one that was actually queried.
            guard authorizationURL.host == issuer.host, tokenURL.host == issuer.host else {
                throw OAuthError.providerMisconfigured(detail: .endpointHostMismatch(issuer: issuer))
            }

            // Revocation and JWKS are *not* held to the same-host rule: unlike the pair above,
            // hosting them on a sibling domain is ordinary practice among large providers, and
            // neither one can redirect a code exchange. They still must be HTTPS, and they are
            // rejected rather than silently dropped when present-but-unusable — a swallowed
            // `jwks_uri` would resurface much later as an unexplained ID-token failure.
            let revocationURL = try validated(document.revocationEndpoint, as: .revocation)
            let jwksURL = try validated(document.jwksURI, as: .jwks)

            return ResolvedEndpoints(
                authorization: authorizationURL, token: tokenURL,
                revocation: revocationURL, jwksURI: jwksURL
            )
        }
    }

    /// Parses and validates an optional discovery-document URL: absent stays absent, present
    /// must be usable.
    private func validated(_ raw: String?, as role: EndpointRole) throws(OAuthError) -> URL? {
        guard let raw else { return nil }
        guard let url = URL(string: raw) else {
            throw OAuthError.providerMisconfigured(detail: .malformedEndpoint(role: role))
        }
        try EndpointValidation.validateServerEndpoint(url, as: role)
        return url
    }
}
