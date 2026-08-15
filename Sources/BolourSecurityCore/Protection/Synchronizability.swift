/// Whether a stored item is confined to this device or may sync via iCloud Keychain.
///
/// ``thisDeviceOnly`` is the default in every construct that accepts a synchronizability,
/// so items never leave the device unless an app opts in explicitly and visibly.
public enum Synchronizability: Sendable, Hashable {
    /// The item never leaves this device. The default everywhere.
    case thisDeviceOnly
    /// The item may sync through iCloud Keychain. An explicit opt-in.
    case synchronizable
}
