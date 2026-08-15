import Foundation

/// The error contract every BolourSecurity module speaks.
///
/// Each module defines its own typed error enum (`KeychainError`, `CryptoError`, …)
/// conforming to `SecurityError` and throws it via typed `throws`. Every conforming case
/// answers three questions in its messages: what failed, the most likely cause, and a
/// recovery suggestion — error messages are part of the reviewed API surface.
///
/// - Important: **Redaction contract.** No conforming type may ever carry key material,
///   plaintext, tokens, or credentials in `errorDescription`, `debugDescription`, or any
///   other description. This is enforced in review and tests. When an error needs to point
///   at an item, it names the *key*, never the *value*.
public protocol SecurityError: Error, LocalizedError,
                               CustomDebugStringConvertible, Sendable {
    /// Whether retrying, or a user action, can plausibly make the operation succeed.
    ///
    /// `true` for conditions like a locked device or a cancelled biometric prompt;
    /// `false` for programmer errors or structurally impossible requests.
    var failureIsRecoverable: Bool { get }
}
