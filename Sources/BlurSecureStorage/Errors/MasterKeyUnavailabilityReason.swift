/// Why a vault's master key could not be obtained.
public enum MasterKeyUnavailabilityReason: Sendable, Hashable {
    /// The stored key material was not 32 bytes — corrupted or from an incompatible format.
    case corruptStoredKey
    /// The vault requires presence but no `AuthenticatedContext` was supplied.
    case presenceRequired
}
