import LocalAuthentication

/// The real `PolicyEvaluating` conformer: one fresh `LAContext` per instance, matching
/// `BiometricAuthenticator`'s "fresh context per `authenticate` call" contract.
///
/// `LAContext` is not `Sendable` and Apple's own docs warn against concurrent use of a single
/// instance; a lock around every access is the documented justification for `@unchecked Sendable`
/// (ADR-0003) — the same pattern `SecureBytes` and `SecureSessionDelegate` already use in this
/// package for a non-Sendable-by-nature type held behind a value/reference boundary.
final class LAContextEvaluator: PolicyEvaluating, @unchecked Sendable {
    private let lock = NSLock()
    private let context = LAContext()

    func canEvaluatePolicy(_ policy: LAPolicy) -> PolicyAvailability {
        lock.lock(); defer { lock.unlock() }
        var nsError: NSError?
        let canEvaluate = context.canEvaluatePolicy(policy, error: &nsError)
        let code = nsError.flatMap { LAError.Code(rawValue: $0.code) }
        return PolicyAvailability(canEvaluate: canEvaluate, error: code, biometryType: context.biometryType)
    }

    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping @Sendable (Bool, (any Error)?) -> Void) {
        // Not held under `lock` for the duration of the call: this triggers system UI and may
        // be outstanding for as long as the user takes to respond, and `LAContext` serializes
        // its own evaluation internally — holding our lock here would only block unrelated
        // property reads on this same instance for no benefit.
        context.evaluatePolicy(policy, localizedReason: localizedReason, reply: reply)
    }

    var evaluatedPolicyDomainState: Data? {
        lock.lock(); defer { lock.unlock() }
        return context.evaluatedPolicyDomainState
    }

    func setBiometryReuseDuration(_ duration: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        context.touchIDAuthenticationAllowableReuseDuration = duration
    }

    func invalidateContext() {
        lock.lock(); defer { lock.unlock() }
        context.invalidate()
    }

    var platformContext: AnyObject { context }
}
