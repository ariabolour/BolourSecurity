/// A subset of RFC 6749 §5.2 error codes providers return from the token endpoint — the ones
/// this module gives distinct handling to. Anything else surfaces via `codeExchangeFailed` with
/// `providerError: nil` and the HTTP status code instead.
public enum ProviderErrorCode: Sendable, Hashable {
    case invalidGrant
    case invalidClient
    case invalidRequest
    case unauthorizedClient
    case unsupportedGrantType
    case invalidScope

    init?(rawValue: String) {
        switch rawValue {
        case "invalid_grant": self = .invalidGrant
        case "invalid_client": self = .invalidClient
        case "invalid_request": self = .invalidRequest
        case "unauthorized_client": self = .unauthorizedClient
        case "unsupported_grant_type": self = .unsupportedGrantType
        case "invalid_scope": self = .invalidScope
        default: return nil
        }
    }
}
