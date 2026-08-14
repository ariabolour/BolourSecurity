import Foundation
import BlurSecurityCore
import BlurJWT

/// The closed failure domain of `BlurOAuth`.
public enum OAuthError: SecurityError {
    /// The user's own decision, distinct from every protocol failure below.
    case userCancelledSignIn
    case discoveryFailed(issuer: URL, underlying: any Error & Sendable)
    /// The `state` returned on the redirect didn't match what this attempt generated — a CSRF
    /// tripwire. Fails loudly on purpose; there is no lenient mode.
    case stateMismatch
    case codeExchangeFailed(statusCode: Int?, providerError: ProviderErrorCode?)
    case idTokenVerificationFailed(underlying: JWTError)
    case refreshFailed(underlying: any Error & Sendable)
    case sessionInvalidated(SessionInvalidationReason)
    case providerMisconfigured(detail: MisconfigurationDetail)

    public var failureIsRecoverable: Bool {
        switch self {
        case .userCancelledSignIn, .discoveryFailed, .codeExchangeFailed, .refreshFailed:
            return true
        case .stateMismatch, .idTokenVerificationFailed, .sessionInvalidated, .providerMisconfigured:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .userCancelledSignIn:
            return "The user cancelled sign-in."
        case .discoveryFailed(let issuer, let underlying):
            return "OIDC discovery failed for issuer “\(issuer)”: \(underlying)."
        case .stateMismatch:
            return "The authorization response's state did not match this attempt's state."
        case .codeExchangeFailed(let statusCode, let providerError):
            let status = statusCode.map { "HTTP \($0)" } ?? "no HTTP status"
            let provider = providerError.map { " (\($0))" } ?? ""
            return "Code exchange failed: \(status)\(provider)."
        case .idTokenVerificationFailed(let underlying):
            return "ID token verification failed: \(underlying.errorDescription ?? "unknown")."
        case .refreshFailed(let underlying):
            return "Token refresh failed: \(underlying)."
        case .sessionInvalidated(let reason):
            return "The session was invalidated (\(reason))."
        case .providerMisconfigured(let detail):
            return "The provider is misconfigured (\(detail))."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .userCancelledSignIn:
            return nil
        case .discoveryFailed:
            return "Confirm the issuer URL and network connectivity, then retry."
        case .stateMismatch:
            return "Restart sign-in; never retry the same authorization response."
        case .codeExchangeFailed:
            return "Restart sign-in."
        case .idTokenVerificationFailed:
            return "Confirm the provider's signing keys and clock are correct."
        case .refreshFailed:
            return "Retry once; if it recurs, route the user back to sign-in."
        case .sessionInvalidated:
            return "Route the user to sign-in."
        case .providerMisconfigured:
            return "Fix the provider configuration; this is a setup error, not a transient failure."
        }
    }

    public var debugDescription: String {
        "OAuthError(\(errorDescription ?? "unknown"))"
    }
}
