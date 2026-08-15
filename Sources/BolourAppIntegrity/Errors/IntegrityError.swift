import Foundation
import BolourSecurityCore

/// The closed failure domain of `AttestationService` and `DeviceCheckToken`.
public enum IntegrityError: SecurityError {
    case unsupported(UnsupportedReason)
    /// No attestation exists yet. Recovery: `attestKey(challenge:)`.
    case keyNotAttested
    /// The OS revoked the key (device restore, app reinstall). Recovery: `resetAttestation()`
    /// then `attestKey(challenge:)`.
    case keyInvalidated
    case attestationRejected(underlying: any Error & Sendable)
    /// A structural misuse — attesting without a real server-issued challenge.
    ///
    /// - Note: **Honest limit.** `ServerChallenge` is a mandatory, non-optional parameter of
    ///   `attestKey(challenge:)`, so the type system already makes "forgot to pass a challenge"
    ///   a compile error — this case is not reachable through the public API today. It stays
    ///   part of the closed domain for documentation/API-parity with the design (matching
    ///   `BolourNetworkSecurity.PinningEnforcementError.tlsVersionBelowMinimum`'s precedent: a
    ///   named, real failure mode the current integration prevents structurally rather than by
    ///   throwing it).
    case serverChallengeRequired
    case rateLimited(retryAfter: Duration?)
    case underlying(any Error & Sendable)

    public var failureIsRecoverable: Bool {
        switch self {
        case .keyNotAttested, .keyInvalidated, .rateLimited:
            return true
        case .unsupported, .attestationRejected, .serverChallengeRequired, .underlying:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .unsupported(let reason):
            return "App Attest is not available (\(reason))."
        case .keyNotAttested:
            return "No key has been attested yet."
        case .keyInvalidated:
            return "The attestation key was invalidated by the OS (device restore or app reinstall)."
        case .attestationRejected(let underlying):
            return "Attestation or assertion was rejected: \(underlying)."
        case .serverChallengeRequired:
            return "A server-issued ServerChallenge is required; a locally generated value is not acceptable."
        case .rateLimited(let retryAfter):
            if let retryAfter { return "Rate limited by the App Attest service; retry after \(retryAfter)." }
            return "Rate limited by the App Attest service."
        case .underlying(let error):
            return "A lower-layer operation failed: \(error)."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .unsupported:
            return "Fall back to a lower-assurance signal (DeviceCheck) or skip integrity checks on this device."
        case .keyNotAttested:
            return "Call attestKey(challenge:) with a fresh server-issued challenge before requesting assertions."
        case .keyInvalidated:
            return "Call resetAttestation(), then attestKey(challenge:) to re-enroll."
        case .attestationRejected:
            return "Confirm the server challenge is fresh and the app's entitlements/environment match the server's expectations."
        case .serverChallengeRequired:
            return "Fetch a challenge from your server; never synthesize one on-device."
        case .rateLimited:
            return "Back off and retry later."
        case .underlying:
            return nil
        }
    }

    public var debugDescription: String {
        "IntegrityError(\(errorDescription ?? "unknown"))"
    }
}
