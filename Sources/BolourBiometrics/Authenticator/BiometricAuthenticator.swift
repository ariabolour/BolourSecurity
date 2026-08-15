import LocalAuthentication
import BolourSecurityCore

/// Face ID, Touch ID, Optic ID, and passcode — as one coherent policy API.
///
/// `LAContext`'s stateful, error-code-driven dance is replaced with: describe what assurance you
/// need as a policy, call one async method, and receive either a scoped ``AuthenticatedContext``
/// or a typed error that says exactly which fallback is appropriate. There is no `-> Bool`
/// overload: success yields a capability, failure throws, so "checked biometrics, then read the
/// secret without any linkage" — the classic bypassable pattern — doesn't arise.
public struct BiometricAuthenticator: Sendable {
    private let logger: (any SecurityEventLogger)?
    private let makeEvaluator: @Sendable () -> any PolicyEvaluating

    public init(logger: (any SecurityEventLogger)? = nil) {
        self.init(logger: logger, makeEvaluator: { LAContextEvaluator() })
    }

    /// Test-only: substitutes a scripted `PolicyEvaluating` double for the real `LAContext` box.
    init(logger: (any SecurityEventLogger)?, makeEvaluator: @escaping @Sendable () -> any PolicyEvaluating) {
        self.logger = logger
        self.makeEvaluator = makeEvaluator
    }

    /// Introspects without prompting. Evaluated fresh every call — the OS can change enrollment,
    /// lockout, or passcode state between calls, so callers should check late, not early.
    public func availability() -> BiometryAvailability {
        let evaluator = makeEvaluator()
        // `.deviceOwnerAuthenticationWithBiometrics` is unavailable on watchOS (no biometry
        // hardware, no biometry-only LAPolicy case there). Probing `.deviceOwnerAuthentication`
        // for both is safe, not just a workaround: `.folding` only reports a biometric-specific
        // result (`.available`/`.notEnrolled`/`.lockedOut`) when the probe also resolves a
        // `BiometryKind`, and watchOS never resolves one (no Face/Touch/Optic ID) — so this
        // still folds correctly to `.passcodeOnly`/`.unavailable` there, never a false positive.
        #if os(watchOS)
        let biometricProbe = evaluator.canEvaluatePolicy(.deviceOwnerAuthentication)
        #else
        let biometricProbe = evaluator.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)
        #endif
        let passcodeProbe = evaluator.canEvaluatePolicy(.deviceOwnerAuthentication)
        return .folding(biometricProbe: biometricProbe, passcodeProbe: passcodeProbe)
    }

    /// Authenticates. May present system UI; `reason` is mandatory and typed.
    ///
    /// A fresh evaluator (and, in production, a fresh `LAContext`) is created per call — contexts
    /// are never implicitly reused across logical operations. `reuseWindow` makes reuse an
    /// explicit, bounded decision instead (`.seconds(0)`, the default, requires fresh
    /// authentication every time).
    public func authenticate(
        reason: AuthenticationReason,
        policy: AuthenticationPolicy = .biometry(fallback: .devicePasscode),
        reuseWindow: Duration = .seconds(0)
    ) async throws(BiometricError) -> AuthenticatedContext {
        let evaluator = makeEvaluator()
        let laPolicy = policy.laPolicy
        evaluator.setBiometryReuseDuration(reuseWindow.timeInterval)

        let probe = evaluator.canEvaluatePolicy(laPolicy)
        guard probe.canEvaluate else {
            logger?.log(.authenticationFailed)
            throw BiometricError.mapping(probe.error)
        }

        do {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                evaluator.evaluatePolicy(laPolicy, localizedReason: reason.resolvedString) { success, error in
                    if success {
                        continuation.resume()
                    } else {
                        continuation.resume(throwing: error ?? LAError(.authenticationFailed))
                    }
                }
            }
        } catch {
            logger?.log(.authenticationFailed)
            throw BiometricError.mapping((error as? LAError)?.code)
        }

        logger?.log(.authenticationSucceeded)
        return AuthenticatedContext(
            method: .inferring(biometryKind: probe.biometryKind, policy: policy),
            evaluator: evaluator,
            authenticatedAt: ContinuousClock().now
        )
    }
}

extension AuthenticationMethod {
    /// LocalAuthentication doesn't report which mechanism satisfied a policy, only that one did
    /// — see the honest-limits note on ``AuthenticationMethod`` itself.
    fileprivate static func inferring(biometryKind: BiometryKind?, policy: AuthenticationPolicy) -> AuthenticationMethod {
        if case .userPresence = policy, biometryKind == nil {
            return .watch
        }
        switch biometryKind {
        case .faceID: return .faceID
        case .touchID: return .touchID
        case .opticID: return .opticID
        case nil: return .passcode
        }
    }
}

extension Duration {
    fileprivate var timeInterval: TimeInterval {
        let components = self.components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1e18
    }
}
