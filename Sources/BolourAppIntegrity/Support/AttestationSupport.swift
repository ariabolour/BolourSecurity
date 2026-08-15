/// Whether this device/build can attest.
public enum AttestationSupport: Sendable, Hashable {
    case supported
    case unsupported(reason: UnsupportedReason)
}

/// Why attestation isn't available.
public enum UnsupportedReason: Sendable, Hashable {
    /// Running on the iOS/watchOS/visionOS Simulator — App Attest never works there.
    case simulator
    /// The OS/hardware combination doesn't support App Attest.
    case platform
    /// MDM/managed-device policy restricts it.
    ///
    /// - Note: **Honest limit.** `DCAppAttestService.isSupported` is a single boolean — Apple's
    ///   API gives no way to distinguish "MDM-restricted" from "platform unsupported." This case
    ///   exists for API completeness (matching the module's design) but is never actually
    ///   produced today; unsupported non-simulator devices map to `.platform`.
    case managedDevice
}
