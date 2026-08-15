import Testing
import LocalAuthentication
@testable import BolourBiometrics

@Suite("BiometryAvailability folding")
struct BiometryAvailabilityTests {

    @Test("biometry available")
    func available() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryKind: .faceID),
            passcodeProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryKind: .faceID)
        )
        #expect(result == .available(.faceID))
    }

    @Test("biometry hardware present but not enrolled")
    func notEnrolled() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotEnrolled, biometryKind: .touchID),
            passcodeProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryKind: .touchID)
        )
        #expect(result == .notEnrolled(.touchID))
    }

    @Test("biometry locked out")
    func lockedOut() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryLockout, biometryKind: .opticID),
            passcodeProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryKind: .opticID)
        )
        #expect(result == .lockedOut(.opticID))
    }

    @Test("no biometric hardware, but a passcode is set")
    func passcodeOnly() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotAvailable, biometryKind: nil),
            passcodeProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryKind: nil)
        )
        #expect(result == .passcodeOnly)
    }

    @Test("no passcode set at all")
    func noPasscode() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotAvailable, biometryKind: nil),
            passcodeProbe: PolicyAvailability(canEvaluate: false, error: .passcodeNotSet, biometryKind: nil)
        )
        #expect(result == .unavailable(reason: .passcodeNotSet))
    }

    @Test("restricted by MDM/parental-controls policy")
    func restricted() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotAvailable, biometryKind: nil),
            passcodeProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotAvailable, biometryKind: nil)
        )
        #expect(result == .unavailable(reason: .restrictedByPolicy))
    }

    @Test("an unrecognized failure falls back to the generic unavailable reason")
    func unrecognizedFailure() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .invalidContext, biometryKind: nil),
            passcodeProbe: PolicyAvailability(canEvaluate: false, error: .invalidContext, biometryKind: nil)
        )
        #expect(result == .unavailable(reason: .noBiometricHardwareOrPasscode))
    }
}
