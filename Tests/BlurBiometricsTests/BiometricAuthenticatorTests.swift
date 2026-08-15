import Testing
import LocalAuthentication
@testable import BlurBiometrics

@Suite("BiometricAuthenticator")
struct BiometricAuthenticatorTests {

    @Test("a successful evaluation yields an AuthenticatedContext with the inferred method")
    func success() async throws {
        let evaluator = FakePolicyEvaluating(
            canEvaluateResult: PolicyAvailability(canEvaluate: true, error: nil, biometryKind: .faceID),
            evaluateSuccess: true
        )
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: { evaluator })
        let context = try await authenticator.authenticate(reason: AuthenticationReason(verbatim: "test"))
        #expect(context.method == .faceID)
        #expect(context.authenticationContext === evaluator)
    }

    @Test("canEvaluatePolicy failing throws before any prompt is attempted")
    func canEvaluateFailureThrowsWithoutPrompting() async {
        let evaluator = FakePolicyEvaluating(
            canEvaluateResult: PolicyAvailability(canEvaluate: false, error: .biometryNotEnrolled, biometryKind: .faceID)
        )
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: { evaluator })
        await #expect(throws: BiometricError.biometryNotEnrolled) {
            _ = try await authenticator.authenticate(reason: AuthenticationReason(verbatim: "test"))
        }
        #expect(evaluator.lastEvaluatedPolicy == nil)
    }

    @Test("evaluatePolicy failing maps the LAError through BiometricError.mapping")
    func evaluateFailureMapsError() async {
        let evaluator = FakePolicyEvaluating(evaluateSuccess: false, evaluateError: LAError(.userCancel))
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: { evaluator })
        await #expect(throws: BiometricError.userCancelled) {
            _ = try await authenticator.authenticate(reason: AuthenticationReason(verbatim: "test"))
        }
    }

    @Test("evaluatePolicy failing with no error at all still fails closed")
    func evaluateFailureWithNoErrorStillThrows() async {
        let evaluator = FakePolicyEvaluating(evaluateSuccess: false, evaluateError: nil)
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: { evaluator })
        await #expect(throws: (any Error).self) {
            _ = try await authenticator.authenticate(reason: AuthenticationReason(verbatim: "test"))
        }
    }

    @Test("reuseWindow is forwarded to the evaluator as a TimeInterval")
    func reuseWindowForwarded() async throws {
        let evaluator = FakePolicyEvaluating()
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: { evaluator })
        _ = try await authenticator.authenticate(reason: AuthenticationReason(verbatim: "test"), reuseWindow: .seconds(10))
        #expect(evaluator.lastReuseDuration == 10)
    }

    @Test("policy selects the LAPolicy that is actually evaluated", arguments: [
        (AuthenticationPolicy.biometry(fallback: .none), LAPolicy.deviceOwnerAuthenticationWithBiometrics),
        (.biometry(fallback: .devicePasscode), .deviceOwnerAuthentication),
        (.devicePasscodeOnly, .deviceOwnerAuthentication),
    ])
    func policySelectsLAPolicy(policy: AuthenticationPolicy, expected: LAPolicy) async throws {
        let evaluator = FakePolicyEvaluating()
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: { evaluator })
        _ = try await authenticator.authenticate(reason: AuthenticationReason(verbatim: "test"), policy: policy)
        #expect(evaluator.lastEvaluatedPolicy?.rawValue == expected.rawValue)
    }

    @Test("invalidate() reaches the underlying evaluator")
    func invalidateReachesEvaluator() async throws {
        let evaluator = FakePolicyEvaluating()
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: { evaluator })
        let context = try await authenticator.authenticate(reason: AuthenticationReason(verbatim: "test"))
        #expect(!evaluator.invalidateCalled)
        context.invalidate()
        #expect(evaluator.invalidateCalled)
    }

    @Test("availability() wires canEvaluatePolicy results through the folding logic")
    func availabilityWiring() {
        let evaluator = FakePolicyEvaluating(
            canEvaluateResult: PolicyAvailability(canEvaluate: true, error: nil, biometryKind: .touchID)
        )
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: { evaluator })
        #expect(authenticator.availability() == .available(.touchID))
    }

    @Test("concurrent authenticate calls each get an independently fresh evaluator")
    func concurrentCallsAreIndependent() async throws {
        let authenticator = BiometricAuthenticator(logger: nil, makeEvaluator: {
            let evaluator = FakePolicyEvaluating()
            evaluator.evaluateDelay = .milliseconds(20)
            return evaluator
        })

        let identities = try await withThrowingTaskGroup(of: ObjectIdentifier.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    let context = try await authenticator.authenticate(reason: AuthenticationReason(verbatim: "test"))
                    return ObjectIdentifier(context.authenticationContext!)
                }
            }
            var results: [ObjectIdentifier] = []
            for try await id in group { results.append(id) }
            return results
        }
        // No shared mutable state races: 8 concurrent calls, 8 genuinely distinct evaluators —
        // never an accidental reuse of one context across logical operations.
        #expect(identities.count == 8)
        #expect(Set(identities).count == 8)
    }
}
