import LocalAuthentication
@testable import BlurBiometrics

/// A scripted `PolicyEvaluating` double — every `BiometricAuthenticator` path is driven through
/// this rather than a real `LAContext`, so the full `LAError` → `BiometricError` mapping and
/// every `authenticate` outcome is testable without a device or enrolled biometry.
final class FakePolicyEvaluating: PolicyEvaluating, @unchecked Sendable {
    private let lock = NSLock()

    var canEvaluateResult: PolicyAvailability
    var evaluateSuccess: Bool
    var evaluateError: Error?
    var evaluateDelay: Duration?
    var domainState: Data?

    private var _lastEvaluatedPolicy: LAPolicy?
    private var _lastReuseDuration: TimeInterval?
    private var _invalidateCalled = false

    var lastEvaluatedPolicy: LAPolicy? { lock.lock(); defer { lock.unlock() }; return _lastEvaluatedPolicy }
    var lastReuseDuration: TimeInterval? { lock.lock(); defer { lock.unlock() }; return _lastReuseDuration }
    var invalidateCalled: Bool { lock.lock(); defer { lock.unlock() }; return _invalidateCalled }

    init(
        canEvaluateResult: PolicyAvailability = PolicyAvailability(canEvaluate: true, error: nil, biometryType: .faceID),
        evaluateSuccess: Bool = true,
        evaluateError: Error? = nil,
        domainState: Data? = nil
    ) {
        self.canEvaluateResult = canEvaluateResult
        self.evaluateSuccess = evaluateSuccess
        self.evaluateError = evaluateError
        self.domainState = domainState
    }

    func canEvaluatePolicy(_ policy: LAPolicy) -> PolicyAvailability { canEvaluateResult }

    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping @Sendable (Bool, (any Error)?) -> Void) {
        lock.lock(); _lastEvaluatedPolicy = policy; lock.unlock()
        let success = evaluateSuccess
        let error = evaluateError
        if let delay = evaluateDelay {
            Task {
                try? await Task.sleep(for: delay)
                reply(success, error)
            }
        } else {
            reply(success, error)
        }
    }

    var evaluatedPolicyDomainState: Data? { domainState }

    func setBiometryReuseDuration(_ duration: TimeInterval) {
        lock.lock(); _lastReuseDuration = duration; lock.unlock()
    }

    func invalidateContext() {
        lock.lock(); _invalidateCalled = true; lock.unlock()
    }

    var platformContext: AnyObject { self }
}
