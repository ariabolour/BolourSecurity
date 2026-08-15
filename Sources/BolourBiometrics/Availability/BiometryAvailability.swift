import LocalAuthentication

/// The device's current ability to authenticate its owner — folded from `canEvaluatePolicy`'s
/// boolean + error + biometry-type triple into one exhaustive value, evaluated fresh at call
/// time (the OS can change this between calls: enrollment, lockout, and passcode state are all
/// mutable, so "check late, not early").
public enum BiometryAvailability: Sendable, Hashable {
    case available(BiometryKind)
    /// Hardware exists but nothing is enrolled.
    case notEnrolled(BiometryKind)
    /// Too many failures; the device passcode will clear the lockout.
    case lockedOut(BiometryKind)
    /// No biometric hardware, but a device passcode is set.
    case passcodeOnly
    case unavailable(reason: UnavailabilityReason)

    /// Folds a biometry-specific probe and, when biometry alone didn't resolve things, a
    /// device-owner-authentication probe (which also accepts the passcode fallback) into one
    /// verdict. A pure function so every branch is a table-driven unit test with no `LAContext`
    /// involved.
    static func folding(biometricProbe: PolicyAvailability, passcodeProbe: PolicyAvailability) -> BiometryAvailability {
        if biometricProbe.canEvaluate, let kind = biometricProbe.biometryKind {
            return .available(kind)
        }
        // `.biometryNotEnrolled`/`.biometryLockout` are unavailable on watchOS (no biometry
        // hardware, no biometry-specific LAError codes there) — but this branch is already
        // unreachable on watchOS regardless: `biometryKind` never resolves there (see
        // `LAContextEvaluator.resolvedBiometryKind()`), so the `let kind = ...` guard below
        // never succeeds on that platform. Gating this out for watchOS removes dead,
        // non-compiling code without changing behavior anywhere.
        #if !os(watchOS)
        if let code = biometricProbe.error, let kind = biometricProbe.biometryKind {
            switch code {
            case .biometryNotEnrolled: return .notEnrolled(kind)
            case .biometryLockout: return .lockedOut(kind)
            default: break
            }
        }
        #endif
        if passcodeProbe.canEvaluate {
            return .passcodeOnly
        }
        return .unavailable(reason: UnavailabilityReason(passcodeProbeError: passcodeProbe.error))
    }
}

extension UnavailabilityReason {
    init(passcodeProbeError code: LAError.Code?) {
        switch code {
        case .passcodeNotSet: self = .passcodeNotSet
        // `.biometryNotAvailable` is unavailable on watchOS (no biometry-specific LAError codes
        // there); `.noBiometricHardwareOrPasscode` below is the correct fallback for a platform
        // that has no biometric hardware at all.
        #if !os(watchOS)
        case .biometryNotAvailable: self = .restrictedByPolicy
        #endif
        default: self = .noBiometricHardwareOrPasscode
        }
    }
}
