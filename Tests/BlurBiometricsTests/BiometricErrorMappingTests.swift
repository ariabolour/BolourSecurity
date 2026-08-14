import Testing
import LocalAuthentication
@testable import BlurBiometrics

@Suite("Every LAError maps to exactly one BiometricError")
struct BiometricErrorMappingTests {

    @Test(
        "documented mapping table",
        arguments: [
            (LAError.Code.authenticationFailed, BiometricError.authenticationFailed),
            (.userCancel, .userCancelled),
            (.userFallback, .userChoseFallback),
            (.systemCancel, .systemCancelled),
            (.appCancel, .systemCancelled),
            (.passcodeNotSet, .passcodeNotSet),
            (.biometryNotEnrolled, .biometryNotEnrolled),
            (.biometryLockout, .biometryLockedOut),
            (.biometryNotAvailable, .notAvailable(.noBiometricHardwareOrPasscode)),
            (.invalidContext, .notAvailable(.contextInvalidated)),
            (.notInteractive, .notAvailable(.contextInvalidated)),
        ] as [(LAError.Code, BiometricError)]
    )
    func mapping(code: LAError.Code, expected: BiometricError) {
        #expect(BiometricError.mapping(code) == expected)
    }

    @Test("a nil code (context invalidated mid-evaluation) maps to notAvailable(.contextInvalidated)")
    func nilCode() {
        #expect(BiometricError.mapping(nil) == .notAvailable(.contextInvalidated))
    }

    @Test(
        "failureIsRecoverable reflects whether a retry or user action can plausibly help",
        arguments: [
            (BiometricError.userCancelled, true),
            (.userChoseFallback, true),
            (.biometryLockedOut, true),
            (.authenticationFailed, true),
            (.systemCancelled, true),
            (.biometryNotEnrolled, false),
            (.passcodeNotSet, false),
            (.notAvailable(.contextInvalidated), false),
        ]
    )
    func recoverability(error: BiometricError, expected: Bool) {
        #expect(error.failureIsRecoverable == expected)
    }
}
