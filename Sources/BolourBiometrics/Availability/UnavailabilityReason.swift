/// Why neither biometry nor passcode authentication is currently possible.
public enum UnavailabilityReason: Sendable, Hashable {
    /// No biometric hardware, and no device passcode is set either.
    case noBiometricHardwareOrPasscode
    /// A device passcode has not been set.
    case passcodeNotSet
    /// Enrolled biometry exists but the sensor is disconnected (external sensors, macOS).
    case biometryDisconnected
    /// Companion-device (Apple Watch) approval was requested but no companion is available.
    case companionDeviceUnavailable
    /// Biometry is present but restricted by MDM/parental-controls policy.
    case restrictedByPolicy
    /// The evaluation context became invalid, or evaluation was attempted from a non-interactive
    /// context (e.g. an app extension). Not user-facing; indicates a caller bug.
    case contextInvalidated
}
