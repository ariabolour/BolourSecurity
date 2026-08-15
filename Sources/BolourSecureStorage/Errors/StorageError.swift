import Foundation
import BolourSecurityCore

/// The closed failure domain of `Vault` and `TokenStore`.
public enum StorageError: SecurityError {
    /// A presence-gated vault was opened or accessed without a valid `AuthenticatedContext`.
    case vaultLocked(VaultName)
    case pathNotFound(VaultPath)
    /// Tamper or corruption: fails closed rather than returning partial or unauthenticated
    /// plaintext.
    case integrityCheckFailed(VaultPath)
    case masterKeyUnavailable(reason: MasterKeyUnavailabilityReason)
    case storageExhausted
    /// A lower-layer failure (Foundation file I/O, `BolourKeychain`, `BolourCrypto`) that doesn't map
    /// to one of the cases above. Preserves the original error rather than lossily collapsing it.
    case underlying(any Error & Sendable)

    public var failureIsRecoverable: Bool {
        switch self {
        case .vaultLocked, .storageExhausted:
            return true
        case .masterKeyUnavailable(let reason):
            return reason == .presenceRequired
        case .pathNotFound, .integrityCheckFailed, .underlying:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .vaultLocked(let name):
            return "Vault “\(name.rawValue)” is presence-gated and no valid authentication context was supplied."
        case .pathNotFound(let path):
            return "No item exists at vault path “\(path.storageKey)”."
        case .integrityCheckFailed(let path):
            return "The item at vault path “\(path.storageKey)” failed its integrity check (tampered or corrupted)."
        case .masterKeyUnavailable(let reason):
            return "The vault's master key is unavailable (\(reason))."
        case .storageExhausted:
            return "The device has insufficient storage to complete this operation."
        case .underlying(let error):
            return "A lower-layer operation failed: \(error)."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .vaultLocked:
            return "Authenticate with BolourBiometrics and pass the resulting context to Vault.open(context:)."
        case .pathNotFound:
            return "Confirm the path was written before reading it."
        case .integrityCheckFailed:
            return "Treat the item as lost; restoring from backup, if any, is the only recovery."
        case .masterKeyUnavailable(.presenceRequired):
            return "Authenticate with BolourBiometrics and pass the resulting context to Vault.open(context:)."
        case .masterKeyUnavailable(.corruptStoredKey):
            return "The keychain item backing the master key is corrupt; the vault cannot be recovered in place."
        case .storageExhausted:
            return "Free up device storage and retry."
        case .underlying:
            return nil
        }
    }

    public var debugDescription: String {
        "StorageError(\(errorDescription ?? "unknown"))"
    }
}
