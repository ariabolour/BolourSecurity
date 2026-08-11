/// When a protected item is accessible, and whether it may sync.
///
/// The ecosystem default is ``default`` — `.whenUnlocked(.thisDeviceOnly)` — the strongest
/// setting that still allows normal foreground use.
///
/// - Note: Swift does not permit default values on enum associated values, so the ergonomic
///   no-argument spellings (`.whenUnlocked()`, `.afterFirstUnlock()`) are provided as
///   same-name static factories alongside the associated-value cases. The call sites read
///   exactly as intended; only the mechanism differs.
public enum ProtectionPolicy: Sendable, Hashable {
    /// Accessible only while the device is unlocked. The ecosystem default.
    case whenUnlocked(Synchronizability)
    /// Accessible after the first unlock since boot (background-refresh use cases).
    case afterFirstUnlock(Synchronizability)
    /// Exists only while a passcode is set; removed by the OS if the passcode is removed.
    /// This-device-only by OS design — there is deliberately no sync parameter to misuse.
    case whenPasscodeSet

    /// `.whenUnlocked(.thisDeviceOnly)`.
    public static func whenUnlocked() -> ProtectionPolicy { .whenUnlocked(.thisDeviceOnly) }

    /// `.afterFirstUnlock(.thisDeviceOnly)`.
    public static func afterFirstUnlock() -> ProtectionPolicy { .afterFirstUnlock(.thisDeviceOnly) }

    /// The ecosystem default: `.whenUnlocked(.thisDeviceOnly)`.
    public static var `default`: ProtectionPolicy { .whenUnlocked() }
}
