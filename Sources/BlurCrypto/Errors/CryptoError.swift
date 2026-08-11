import Foundation
import BlurSecurityCore

/// The closed failure domain of every `BlurCrypto` operation.
///
/// No case carries key material, plaintext, or any secret — only sizes, versions, suites, and
/// file URLs, none of which are secrets (see the ``SecurityError`` redaction contract).
public enum CryptoError: SecurityError {
    /// A key was the wrong size for its suite.
    case invalidKeySize(expected: Int, actual: Int)
    /// A key or key representation was malformed.
    case invalidKey
    /// Authenticated encryption failed to produce a sealed message.
    case sealFailed
    /// Authenticated decryption failed — the message was tampered with, truncated, or the wrong key/AAD was used.
    case openFailed
    /// A sealed message could not be parsed.
    case malformedMessage
    /// A sealed message used a format version this build does not understand.
    case unsupportedFormatVersion(UInt8)
    /// The key's cipher suite did not match the sealed message's suite.
    case suiteMismatch(expected: CipherSuite, actual: CipherSuite)
    /// A signing operation failed.
    case signingFailed
    /// A key-derivation operation failed.
    case keyDerivationFailed
    /// Password-hashing parameters were below the enforced security floor.
    case insecureParameters(reason: String)
    /// A file could not be read for streaming hashing.
    case fileUnreadable(URL)

    public var failureIsRecoverable: Bool {
        switch self {
        case .fileUnreadable:
            return true
        case .invalidKeySize, .invalidKey, .sealFailed, .openFailed, .malformedMessage,
             .unsupportedFormatVersion, .suiteMismatch, .signingFailed, .keyDerivationFailed,
             .insecureParameters:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidKeySize(let expected, let actual):
            return "Key was \(actual) bytes; \(expected) were required."
        case .invalidKey:
            return "The key or key representation was malformed."
        case .sealFailed:
            return "Authenticated encryption failed."
        case .openFailed:
            return "Authenticated decryption failed: the message was tampered with, truncated, or the wrong key or associated data was used."
        case .malformedMessage:
            return "The sealed message could not be parsed."
        case .unsupportedFormatVersion(let version):
            return "The sealed message uses format version \(version), which this build does not understand."
        case .suiteMismatch(let expected, let actual):
            return "This key is configured for \(expected), but the message was sealed with \(actual)."
        case .signingFailed:
            return "The signing operation failed."
        case .keyDerivationFailed:
            return "Key derivation failed."
        case .insecureParameters(let reason):
            return "Password-hashing parameters were rejected: \(reason)."
        case .fileUnreadable(let url):
            return "The file at \(url.path) could not be read."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .invalidKeySize:
            return "Provide a 256-bit (32-byte) key, or derive one with KeyDerivation."
        case .openFailed:
            return "Verify the ciphertext is intact and that the same key and associated data used to seal are used to open."
        case .unsupportedFormatVersion:
            return "Upgrade the reading side to a build that supports this message version."
        case .suiteMismatch:
            return "Open the message with a key configured for the same cipher suite it was sealed with."
        case .insecureParameters:
            return "Raise the iteration count to at least the enforced floor."
        case .fileUnreadable:
            return "Confirm the file exists and is readable."
        case .invalidKey, .sealFailed, .malformedMessage, .signingFailed, .keyDerivationFailed:
            return nil
        }
    }

    public var debugDescription: String {
        "CryptoError(\(errorDescription ?? "unknown"))"
    }
}
