/// What proof of user presence is required to access an item.
///
/// - Note: As with ``ProtectionPolicy``, the no-argument `.biometry()` spelling is a static
///   factory (Swift forbids defaults on associated values); it means `.biometry(.currentSet)`.
public enum PresenceRequirement: Sendable, Hashable {
    /// No presence check.
    case none
    /// Any user presence: biometry or the device passcode.
    case userPresence
    /// Biometry only. ``BiometrySet/currentSet`` (the default) invalidates the authorization
    /// if the enrolled biometric set changes.
    case biometry(BiometrySet)
    /// The device passcode specifically.
    case devicePasscode

    /// `.biometry(.currentSet)` — biometry bound to the currently enrolled set.
    public static func biometry() -> PresenceRequirement { .biometry(.currentSet) }

    /// Which enrolled biometrics satisfy a ``PresenceRequirement/biometry(_:)`` requirement.
    public enum BiometrySet: Sendable, Hashable {
        /// Only the biometrics enrolled at store time. A newly added face/fingerprint does
        /// not qualify. The safe default.
        case currentSet
        /// Any currently enrolled biometric qualifies. Explicit, and weaker.
        case anyEnrolled
    }
}
