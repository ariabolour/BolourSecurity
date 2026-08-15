import LocalAuthentication

/// The result of a non-prompting `canEvaluatePolicy` probe.
///
/// Carries `BiometryKind?` rather than `LABiometryType` directly: the latter is
/// `@available(watchOS 11.0, *)`, and Apple Watch has no Face ID/Touch ID/Optic ID hardware at
/// any OS version regardless — resolving to our own always-available type at the one real
/// `LAContext` boundary (`LAContextEvaluator`) keeps that version gate from spreading through
/// every downstream consumer.
struct PolicyAvailability: Sendable {
    let canEvaluate: Bool
    let error: LAError.Code?
    let biometryKind: BiometryKind?
}

/// An internal seam around `LAContext`, so `BiometricAuthenticator` can be driven by a scripted
/// double in tests — covering every `LAError` → `BiometricError` mapping and every
/// `BiometryAvailability` fold exhaustively — without a device or an enrolled biometric.
///
/// `AnyObject`-constrained so a conformer can be handed out, type-erased, as
/// `PresenceAuthenticated.authenticationContext` — the same object used to evaluate the policy
/// is the one `BolourKeychain`/`BolourCrypto` later pass to `kSecUseAuthenticationContext`.
protocol PolicyEvaluating: AnyObject, Sendable {
    /// Probes without prompting. Safe to call more than once on the same instance.
    func canEvaluatePolicy(_ policy: LAPolicy) -> PolicyAvailability
    /// Prompts if needed. The reply shape matches `LAContext`'s own completion-handler API so
    /// the async bridge stays explicit and internal, mirroring `BolourNetworkSecurity`'s challenge
    /// completion-handler bridge.
    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping @Sendable (Bool, (any Error)?) -> Void)
    /// `LAContext.evaluatedPolicyDomainState` — the raw material behind `BiometryState`.
    var evaluatedPolicyDomainState: Data? { get }
    /// Sets `LAContext.touchIDAuthenticationAllowableReuseDuration`.
    func setBiometryReuseDuration(_ duration: TimeInterval)
    /// Ends the session early, matching `LAContext.invalidate()`.
    func invalidateContext()
    /// The underlying platform object, type-erased for `PresenceAuthenticated`.
    var platformContext: AnyObject { get }
}
