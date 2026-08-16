import Foundation

/// Why a provider configuration — supplied directly, or returned by OIDC discovery — was rejected.
public enum MisconfigurationDetail: Sendable, Hashable {
    /// OIDC discovery's `token_endpoint`/`authorization_endpoint` did not share the issuer's
    /// host — mix-up-attack hygiene: discovery metadata is never trusted to redirect the token
    /// exchange to a different host than the one that was actually discovered.
    case endpointHostMismatch(issuer: URL)
    /// Discovery metadata was missing a required endpoint.
    case incompleteDiscoveryDocument
    /// The URL for this role was not HTTPS (or, for a redirect URI, was plain `http`).
    case insecureEndpoint(role: EndpointRole)
    /// The URL for this role was HTTPS-or-better but structurally unusable: no host, embedded
    /// credentials, a fragment, or — for a redirect URI — a scheme no app should register.
    case malformedEndpoint(role: EndpointRole)
    /// The discovery document's own `issuer` field did not match the issuer that was queried
    /// (RFC 8414 §3.3). A provider that disagrees with itself about its identity is one an
    /// attacker may be speaking for.
    case discoveredIssuerMismatch(expected: URL)
}

extension MisconfigurationDetail: CustomStringConvertible {
    public var description: String {
        switch self {
        case .endpointHostMismatch(let issuer):
            return "discovery for “\(issuer)” named endpoints on a different host"
        case .incompleteDiscoveryDocument:
            return "the discovery document was missing a required endpoint"
        case .insecureEndpoint(let role):
            return role == .redirect
                ? "the redirect URI uses plain http; use the app's own scheme, or https"
                : "the \(role) is not https"
        case .malformedEndpoint(let role):
            return "the \(role) is not a usable URL (no host, embedded credentials, a fragment, or an unusable scheme)"
        case .discoveredIssuerMismatch(let expected):
            return "the discovery document's issuer did not match “\(expected)”"
        }
    }
}
