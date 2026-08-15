import LocalAuthentication
import BolourSecurityCore

/// The closed failure domain of biometric/passcode authentication.
///
/// Every `LAError` maps to exactly one case here; the mapping is public documentation
/// (``mapping(_:)``) because apps in regulated industries must justify their fallback flows to
/// auditors.
public enum BiometricError: SecurityError, Hashable {
    /// The user's own decision. Never retry-loop this — re-prompting after a deliberate
    /// cancellation reads as a dark pattern.
    case userCancelled
    /// The user asked for the fallback (passcode) instead of biometry. Honor it; the fallback
    /// UI is the system's own, not something this package re-implements.
    case userChoseFallback
    /// Too many failed attempts; recovery is authenticating with the device passcode.
    case biometryLockedOut
    case biometryNotEnrolled
    case passcodeNotSet
    /// A genuine mismatch after the system's own retry budget was exhausted.
    case authenticationFailed
    /// The app was backgrounded or otherwise interrupted the prompt; safe to retry once.
    case systemCancelled
    case notAvailable(UnavailabilityReason)

    public var failureIsRecoverable: Bool {
        switch self {
        case .userCancelled, .userChoseFallback, .biometryLockedOut, .authenticationFailed, .systemCancelled:
            return true
        case .biometryNotEnrolled, .passcodeNotSet, .notAvailable:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .userCancelled: return "The user cancelled authentication."
        case .userChoseFallback: return "The user chose the passcode fallback instead of biometry."
        case .biometryLockedOut: return "Biometry is locked out after too many failed attempts."
        case .biometryNotEnrolled: return "No biometry is enrolled on this device."
        case .passcodeNotSet: return "No device passcode is set."
        case .authenticationFailed: return "Authentication failed after the system's retry budget was exhausted."
        case .systemCancelled: return "The system cancelled authentication (e.g. the app was backgrounded)."
        case .notAvailable(let reason): return "Authentication is not available (\(reason))."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .userCancelled, .userChoseFallback, .authenticationFailed:
            return nil
        case .biometryLockedOut:
            return "Authenticate with the device passcode to clear the lockout."
        case .biometryNotEnrolled:
            return "Direct the user to Settings to enroll biometry, or fall back to another auth method."
        case .passcodeNotSet:
            return "Direct the user to Settings to set a device passcode."
        case .systemCancelled:
            return "Retry once; if it recurs, stop and let the user re-initiate."
        case .notAvailable:
            return "Fall back to another authentication method for this session."
        }
    }

    public var debugDescription: String {
        "BiometricError(\(errorDescription ?? "unknown"))"
    }

    /// Maps every `LAError` code this package can observe to exactly one `BiometricError`.
    /// `nil`/non-`LAError` inputs (a context invalidated mid-evaluation, an unexpected error
    /// type) map to `.notAvailable(.contextInvalidated)` — a caller bug, not a user-facing state.
    static func mapping(_ code: LAError.Code?) -> BiometricError {
        switch code {
        case .authenticationFailed: return .authenticationFailed
        case .userCancel: return .userCancelled
        case .userFallback: return .userChoseFallback
        case .systemCancel, .appCancel: return .systemCancelled
        case .passcodeNotSet: return .passcodeNotSet
        case .biometryNotEnrolled: return .biometryNotEnrolled
        case .biometryLockout: return .biometryLockedOut
        case .biometryNotAvailable: return .notAvailable(.noBiometricHardwareOrPasscode)
        case .invalidContext, .notInteractive, nil: return .notAvailable(.contextInvalidated)
        default: return .notAvailable(.contextInvalidated)
        }
    }
}
