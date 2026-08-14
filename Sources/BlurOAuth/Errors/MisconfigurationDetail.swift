import Foundation

/// Why a provider's configuration was rejected before any network use of it.
public enum MisconfigurationDetail: Sendable, Hashable {
    /// OIDC discovery's `token_endpoint`/`authorization_endpoint` did not share the issuer's
    /// host — mix-up-attack hygiene: discovery metadata is never trusted to redirect the token
    /// exchange to a different host than the one that was actually discovered.
    case endpointHostMismatch(issuer: URL)
    /// Discovery metadata was missing a required endpoint.
    case incompleteDiscoveryDocument
}
