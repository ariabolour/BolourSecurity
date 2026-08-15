import Foundation
import BolourSecurityCore

/// The closed failure domain of certificate parsing, trust evaluation, and pinning.
///
/// `pinMismatch` deliberately omits the presented hashes: an active MITM should not get free
/// confirmation, from logs apps often upload, of what the app expected versus saw. Full detail is
/// available through the app-controlled `SecurityEvent` channel.
public enum CertificateError: SecurityError {
    case malformedEncoding(detail: MalformationDetail)
    case systemTrustFailed(underlying: OSStatus, host: String)
    case hostnameMismatch(host: String, presented: [SubjectAlternativeName])
    case expired(notAfter: Date)
    case notYetValid(notBefore: Date)
    case pinMismatch(host: String)
    case pinSetExpired(host: String, expiredAt: Date)
    case revocationCheckFailed(host: String)

    public var failureIsRecoverable: Bool {
        switch self {
        case .revocationCheckFailed:
            return true
        case .malformedEncoding, .systemTrustFailed, .hostnameMismatch, .expired,
             .notYetValid, .pinMismatch, .pinSetExpired:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .malformedEncoding(let detail):
            return "The certificate encoding was malformed (\(detail))."
        case .systemTrustFailed(let status, let host):
            return "System trust evaluation failed for “\(host)” (OSStatus \(status))."
        case .hostnameMismatch(let host, _):
            return "The certificate is not valid for host “\(host)”."
        case .expired(let notAfter):
            return "The certificate expired at \(notAfter)."
        case .notYetValid(let notBefore):
            return "The certificate is not valid until \(notBefore)."
        case .pinMismatch(let host):
            return "None of the pinned public keys matched the chain presented for “\(host)”."
        case .pinSetExpired(let host, let expiredAt):
            return "The pin set for “\(host)” expired at \(expiredAt); rotated pins must ship before connections resume."
        case .revocationCheckFailed(let host):
            return "Revocation status could not be determined for “\(host)”."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .pinMismatch:
            return "Confirm the server's certificate and that the app ships current SPKI pins."
        case .pinSetExpired:
            return "Ship an app update with rotated pins; connections fail closed until then."
        case .hostnameMismatch:
            return "Connect to a host covered by the certificate's Subject Alternative Names."
        case .revocationCheckFailed:
            return "Retry; if it persists, the network may be blocking OCSP/CRL checks."
        case .malformedEncoding, .systemTrustFailed, .expired, .notYetValid:
            return nil
        }
    }

    public var debugDescription: String {
        "CertificateError(\(errorDescription ?? "unknown"))"
    }
}

/// Where DER parsing rejected an input. Carries no attacker-useful detail beyond a category.
public enum MalformationDetail: Sendable, Hashable, CustomStringConvertible {
    case truncated
    case indefiniteLength
    case lengthTooLarge
    case unexpectedTag
    case invalidTime
    case invalidObjectIdentifier
    case notACertificate
    case invalidPEM
    case invalidPinEncoding

    public var description: String {
        switch self {
        case .truncated: return "truncated"
        case .indefiniteLength: return "indefinite length (not valid DER)"
        case .lengthTooLarge: return "length too large"
        case .unexpectedTag: return "unexpected tag"
        case .invalidTime: return "invalid time"
        case .invalidObjectIdentifier: return "invalid object identifier"
        case .notACertificate: return "not a certificate"
        case .invalidPEM: return "invalid PEM"
        case .invalidPinEncoding: return "invalid pin encoding (expected base64 of a 32-byte SHA-256)"
        }
    }
}
