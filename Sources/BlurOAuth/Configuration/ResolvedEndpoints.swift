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

            guard let authorizationURL = URL(string: document.authorizationEndpoint),
                  let tokenURL = URL(string: document.tokenEndpoint)
            else {
                throw OAuthError.providerMisconfigured(detail: .incompleteDiscoveryDocument)
            }
            // Mix-up-attack hygiene: discovery metadata is never trusted to redirect the token
            // exchange to a different host than the one that was actually queried.
            guard authorizationURL.host == issuer.host, tokenURL.host == issuer.host else {
                throw OAuthError.providerMisconfigured(detail: .endpointHostMismatch(issuer: issuer))
            }

            return ResolvedEndpoints(
                authorization: authorizationURL, token: tokenURL,
                revocation: document.revocationEndpoint.flatMap(URL.init(string:)),
                jwksURI: document.jwksURI.flatMap(URL.init(string:))
            )
        }
    }
}
