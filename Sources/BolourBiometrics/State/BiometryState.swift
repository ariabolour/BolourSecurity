import LocalAuthentication

/// A snapshot of the enrolled biometric set, for re-enrollment (change) detection.
///
/// Backed by `LAContext.evaluatedPolicyDomainState`, which the OS changes whenever the enrolled
/// biometry set changes (a face/fingerprint added or removed). Persist a captured value and
/// compare later with `==`; inequality means biometry changed since capture — the signal an
/// invalidation policy needs.
public struct BiometryState: Sendable, Hashable {
    private let domainState: Data

    init(domainState: Data) { self.domainState = domainState }

    /// Captures the current state, or `nil` if biometry can't be evaluated at all right now
    /// (no hardware, nothing enrolled — there is no set to snapshot).
    ///
    /// - Note: **Honest limit (watchOS).** Apple Watch has no Face ID/Touch ID/Optic ID
    ///   hardware and `LAPolicy.deviceOwnerAuthenticationWithBiometrics` is unavailable there —
    ///   there is no biometry-specific domain state to snapshot at all, so this always returns
    ///   `nil` on watchOS, the same as the documented "no hardware" case above.
    public static func current() -> BiometryState? {
        #if os(watchOS)
        return nil
        #else
        let evaluator = LAContextEvaluator()
        guard evaluator.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics).canEvaluate,
              let domainState = evaluator.evaluatedPolicyDomainState
        else { return nil }
        return BiometryState(domainState: domainState)
        #endif
    }
}
