import Foundation

/// Which URL in an OAuth configuration a validation failure refers to. Carries no value beyond
/// the role — the URL itself is the caller's own input on the configuration paths, and
/// attacker-controlled text on the discovery path, so it is never echoed back.
public enum EndpointRole: String, Sendable, Hashable, CustomStringConvertible {
    case issuer
    case authorization
    case token
    case revocation
    case jwks
    case redirect

    public var description: String {
        switch self {
        case .issuer: return "issuer"
        case .authorization: return "authorization endpoint"
        case .token: return "token endpoint"
        case .revocation: return "revocation endpoint"
        case .jwks: return "JWKS URI"
        case .redirect: return "redirect URI"
        }
    }
}

/// The URL rules every endpoint in this module is held to, applied at configuration time and
/// again to anything OIDC discovery hands back.
///
/// Discovery metadata arrives over the network. Even fetched from an HTTPS issuer, it is a
/// document that names *other* URLs, and a provider that is compromised, misconfigured, or
/// merely sloppy can name a `http://` token endpoint — at which point the authorization code and
/// the tokens it buys travel in cleartext. Validating only at configuration time would leave
/// that entire class open, so both paths run through here.
enum EndpointValidation {

    /// A server-side endpoint: HTTPS, a real host, no credentials, no fragment.
    static func validateServerEndpoint(_ url: URL, as role: EndpointRole) throws(OAuthError) {
        guard url.scheme?.lowercased() == "https" else {
            throw OAuthError.providerMisconfigured(detail: .insecureEndpoint(role: role))
        }
        guard let host = url.host, !host.isEmpty else {
            throw OAuthError.providerMisconfigured(detail: .malformedEndpoint(role: role))
        }
        // Credentials in the URL would be sent to the provider on every request and land in
        // logs; a fragment is never sent to the server at all, so its presence means the URL is
        // not what whoever wrote it thinks it is.
        guard url.user == nil, url.password == nil, url.fragment == nil else {
            throw OAuthError.providerMisconfigured(detail: .malformedEndpoint(role: role))
        }
    }

    /// The issuer additionally carries no query — RFC 8414 §2 defines the issuer identifier as a
    /// URL with no query or fragment, and `.well-known` discovery appends a path to it.
    static func validateIssuer(_ url: URL) throws(OAuthError) {
        try validateServerEndpoint(url, as: .issuer)
        guard url.query == nil else {
            throw OAuthError.providerMisconfigured(detail: .malformedEndpoint(role: .issuer))
        }
    }

    /// The redirect URI: either an app's own custom scheme or HTTPS, never plain `http`.
    ///
    /// RFC 8252 §7.3 does permit a loopback `http://127.0.0.1` redirect for native apps, and it
    /// is rejected here anyway: this module's only interactive path is
    /// `ASWebAuthenticationSession`, which dispatches callbacks by *scheme*, so a loopback
    /// redirect could never be delivered by this implementation. Accepting one would mean
    /// accepting a configuration that cannot work.
    static func validateRedirectURI(_ url: URL) throws(OAuthError) {
        guard let scheme = url.scheme?.lowercased(), !scheme.isEmpty else {
            throw OAuthError.providerMisconfigured(detail: .malformedEndpoint(role: .redirect))
        }
        guard url.fragment == nil else {
            throw OAuthError.providerMisconfigured(detail: .malformedEndpoint(role: .redirect))
        }
        if scheme == "https" {
            try validateServerEndpoint(url, as: .redirect)
            return
        }
        guard scheme != "http" else {
            throw OAuthError.providerMisconfigured(detail: .insecureEndpoint(role: .redirect))
        }
        // A custom scheme. RFC 3986 §3.1 shapes it; the denylist covers schemes a browser would
        // treat as code or local-file access rather than as an app callback.
        guard isValidURIScheme(scheme), !EndpointValidation.rejectedRedirectSchemes.contains(scheme) else {
            throw OAuthError.providerMisconfigured(detail: .malformedEndpoint(role: .redirect))
        }
    }

    /// Whether `callback` is the redirect URI this configuration registered, compared on the
    /// parts a provider must echo back verbatim: scheme, host, port, and path.
    ///
    /// Query and fragment are excluded deliberately — the query is exactly where the provider
    /// puts `code`/`state`, so it differs by design.
    static func callbackMatchesRedirectURI(_ callback: URL, expected: URL) -> Bool {
        callback.scheme?.lowercased() == expected.scheme?.lowercased()
            && callback.host?.lowercased() == expected.host?.lowercased()
            && callback.port == expected.port
            && callback.path == expected.path
    }

    /// Schemes an app must never register as an OAuth callback: each one hands a URL a browser
    /// or the OS will interpret as code or as local-file access.
    private static let rejectedRedirectSchemes: Set<String> = [
        "javascript", "data", "vbscript", "file", "blob", "about",
    ]

    /// RFC 3986 §3.1: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` — ASCII only, so
    /// `Character.isLetter`/`isNumber` alone won't do (they accept "é" and "٣").
    private static func isValidURIScheme(_ scheme: String) -> Bool {
        guard let first = scheme.first, first.isASCII, first.isLetter else { return false }
        return scheme.allSatisfy { character in
            guard character.isASCII else { return false }
            return character.isLetter || character.isNumber || character == "+" || character == "-" || character == "."
        }
    }
}
