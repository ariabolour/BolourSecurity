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
        ///
        /// - Note: **Honest limit (watchOS).** LocalAuthentication on watchOS has no
        ///   biometry-only policy to ask for at all — there is no Face ID/Touch ID/Optic ID
        ///   hardware on Apple Watch, and `LAPolicy.deviceOwnerAuthenticationWithBiometrics` is
        ///   unavailable there. On watchOS, `.biometry(fallback: .none)` behaves like
        ///   `.biometry(fallback: .devicePasscode)` instead — passcode-inclusive, not
        ///   biometry-or-fail — because that's the strictest policy the platform actually offers.
        case none
    }

    var laPolicy: LAPolicy {
        switch self {
        case .biometry(.devicePasscode), .devicePasscodeOnly:
            return .deviceOwnerAuthentication
        case .biometry(.none):
            // `.deviceOwnerAuthenticationWithBiometrics` (biometry required, no passcode
            // fallback) is unavailable on watchOS — LocalAuthentication there only exposes
            // `.deviceOwnerAuthentication`. Same honest-limit shape as `.devicePasscodeOnly`
            // above: on watchOS, `.biometry(fallback: .none)` actually behaves like
            // `.deviceOwnerAuthentication` (passcode-inclusive), because there is no stricter
            // policy to ask for.
            #if os(watchOS)
            return .deviceOwnerAuthentication
            #else
            return .deviceOwnerAuthenticationWithBiometrics
            #endif
        case .userPresence:
            #if os(macOS)
            return .deviceOwnerAuthenticationWithBiometricsOrWatch
            #else
            return .deviceOwnerAuthentication
            #endif
        }
    }
}
