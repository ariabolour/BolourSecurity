import Foundation
import Security
import BolourSecurityCore

/// The closed failure domain of every `Keychain` operation.
///
/// Each case answers what failed, the most likely cause, and how to fix it (`errorDescription`
/// + `recoverySuggestion`). No case carries stored secret material — only key *names*, group
/// *names*, policies, and `OSStatus` values, none of which are secrets (see the ``SecurityError``
/// redaction contract).
public enum KeychainError: SecurityError {
    /// An operation that requires an existing item found none.
    case itemNotFound(ItemKey)
    /// An add collided with an existing item (surfaced only when add-then-update cannot resolve it).
    case duplicateItem(ItemKey)
    /// A presence-gated item was read without a valid authenticated context.
    case authenticationRequired(ItemKey)
    /// The user authentication backing an access-controlled item failed or was cancelled.
    case authenticationFailed(underlying: OSStatus)
    /// The device was locked and the item's protection policy forbade access.
    case interactionNotAllowed
    /// The device cannot satisfy the requested protection policy (e.g. `.whenPasscodeSet` with no passcode).
    case protectionUnsatisfiable(ProtectionPolicy)
    /// The app lacks the entitlement for the named access group.
    case accessGroupDenied(AccessGroup)
    /// A returned item did not have the expected shape.
    case unexpectedItemShape
    /// A last-resort passthrough of an unmapped `OSStatus`. Never swallowed.
    case underlying(OSStatus)

    public var failureIsRecoverable: Bool {
        switch self {
        case .authenticationRequired, .authenticationFailed, .interactionNotAllowed, .underlying:
            return true
        case .itemNotFound, .duplicateItem, .protectionUnsatisfiable, .accessGroupDenied, .unexpectedItemShape:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .itemNotFound(let key):
            return "No keychain item exists for key “\(key.rawValue)”."
        case .duplicateItem(let key):
            return "A keychain item already exists for key “\(key.rawValue)”."
        case .authenticationRequired(let key):
            return "Item “\(key.rawValue)” is presence-gated and requires user authentication to read."
        case .authenticationFailed:
            return "User authentication failed or was cancelled."
        case .interactionNotAllowed:
            return "The keychain item could not be accessed because the device is locked."
        case .protectionUnsatisfiable(let policy):
            return "The device cannot satisfy the requested protection policy (\(policy))."
        case .accessGroupDenied(let group):
            return "Access to keychain group “\(group.rawValue)” was denied."
        case .unexpectedItemShape:
            return "A keychain item had an unexpected format."
        case .underlying(let status):
            let system = SecCopyErrorMessageString(status, nil) as String?
            return "Keychain operation failed (OSStatus \(status))" + (system.map { ": \($0)" } ?? "") + "."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .itemNotFound:
            return "Confirm the key and this Keychain’s service and access group match where the item was stored."
        case .duplicateItem:
            return "Remove the existing item first, or store again to update it in place."
        case .authenticationRequired:
            return "Provide an authenticated context (see BolourBiometrics), or read from a user-initiated context."
        case .authenticationFailed:
            return "Ask the user to authenticate again."
        case .interactionNotAllowed:
            return "Access the item while the device is unlocked, or use a policy such as .afterFirstUnlock() for background access."
        case .protectionUnsatisfiable:
            return "Ensure a device passcode is set, or choose a less restrictive protection policy."
        case .accessGroupDenied(let group):
            return "Add the keychain access group “\(group.rawValue)” to your app’s Keychain Sharing entitlement and confirm the App ID matches."
        case .unexpectedItemShape, .underlying:
            return nil
        }
    }

    public var debugDescription: String {
        "KeychainError(\(errorDescription ?? "unknown"))"
    }
}
