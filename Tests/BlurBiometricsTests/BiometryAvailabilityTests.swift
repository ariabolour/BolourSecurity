import Testing
import LocalAuthentication
@testable import BlurBiometrics

@Suite("BiometryAvailability folding")
struct BiometryAvailabilityTests {

    @Test("biometry available")
    func available() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryType: .faceID),
            passcodeProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryType: .faceID)
        )
        #expect(result == .available(.faceID))
    }

    @Test("biometry hardware present but not enrolled")
    func notEnrolled() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotEnrolled, biometryType: .touchID),
            passcodeProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryType: .touchID)
        )
        #expect(result == .notEnrolled(.touchID))
    }

    @Test("biometry locked out")
    func lockedOut() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryLockout, biometryType: .opticID),
            passcodeProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryType: .opticID)
        )
        #expect(result == .lockedOut(.opticID))
    }

    @Test("no biometric hardware, but a passcode is set")
    func passcodeOnly() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotAvailable, biometryType: .none),
            passcodeProbe: PolicyAvailability(canEvaluate: true, error: nil, biometryType: .none)
        )
        #expect(result == .passcodeOnly)
    }

    @Test("no passcode set at all")
    func noPasscode() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotAvailable, biometryType: .none),
            passcodeProbe: PolicyAvailability(canEvaluate: false, error: .passcodeNotSet, biometryType: .none)
        )
        #expect(result == .unavailable(reason: .passcodeNotSet))
    }

    @Test("restricted by MDM/parental-controls policy")
    func restricted() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotAvailable, biometryType: .none),
            passcodeProbe: PolicyAvailability(canEvaluate: false, error: .biometryNotAvailable, biometryType: .none)
        )
        #expect(result == .unavailable(reason: .restrictedByPolicy))
    }

    @Test("an unrecognized failure falls back to the generic unavailable reason")
    func unrecognizedFailure() {
        let result = BiometryAvailability.folding(
            biometricProbe: PolicyAvailability(canEvaluate: false, error: .invalidContext, biometryType: .none),
            passcodeProbe: PolicyAvailability(canEvaluate: false, error: .invalidContext, biometryType: .none)
        )
        #expect(result == .unavailable(reason: .noBiometricHardwareOrPasscode))
    }
}
