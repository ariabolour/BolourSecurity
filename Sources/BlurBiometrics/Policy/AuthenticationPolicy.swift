import LocalAuthentication

/// What assurance an `authenticate` call requires.
public enum AuthenticationPolicy: Sendable, Hashable {
    /// Biometry first, with an explicit statement of what happens when it can't proceed.
    case biometry(fallback: Fallback)
    /// The device passcode.
    ///
    /// - Note: **Honest limit.** LocalAuthentication has no policy that skips biometry and goes
    ///   straight to a passcode prompt when biometry hardware is present and enrolled — there is
    ///   no `LAPolicy` case for it. This maps to `.deviceOwnerAuthentication` (the same policy as
    ///   `.biometry(fallback: .devicePasscode)`); on a device with biometry enrolled, the OS may
    ///   still attempt biometry before offering the passcode fallback.
    case devicePasscodeOnly
    /// visionOS companion-device / Apple Watch approval where the OS offers it.
    case userPresence

    public enum Fallback: Sendable, Hashable {
        /// Recommended default: users are never stranded.
        case devicePasscode
        /// Biometry-or-fail: high-assurance flows, explicit choice.
        case none
    }

    var laPolicy: LAPolicy {
        switch self {
        case .biometry(.devicePasscode), .devicePasscodeOnly:
            return .deviceOwnerAuthentication
        case .biometry(.none):
            return .deviceOwnerAuthenticationWithBiometrics
        case .userPresence:
            #if os(macOS)
            return .deviceOwnerAuthenticationWithBiometricsOrWatch
            #else
            return .deviceOwnerAuthentication
            #endif
        }
    }
}
