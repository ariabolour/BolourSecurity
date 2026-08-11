import Foundation
import Security
import BlurSecurityCore

/// The single owner of the mapping from BlurSecurity's typed vocabulary to Keychain Services'
/// `kSec*` dictionaries. No query construction happens anywhere else in the module — this type
/// is the exhaustively-tested seam between our types and the OS.
struct ItemDescriptor: Sendable, Hashable {
    let service: String
    let account: String
    let accessGroup: String?
    let protection: ProtectionPolicy
    let presence: PresenceRequirement

    init(service: String, key: ItemKey, accessGroup: String?,
         protection: ProtectionPolicy, presence: PresenceRequirement) {
        self.service = service
        self.account = key.rawValue
        self.accessGroup = accessGroup
        self.protection = protection
        self.presence = presence
    }

    /// The `kSecAttrAccessible*` constant for a protection policy. Pure and total — every case
    /// of ``ProtectionPolicy`` maps, and the illegal corners are unrepresentable in the type.
    static func accessibleValue(for protection: ProtectionPolicy) -> CFString {
        switch protection {
        case .whenUnlocked(.thisDeviceOnly):
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .whenUnlocked(.synchronizable):
            return kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlock(.thisDeviceOnly):
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .afterFirstUnlock(.synchronizable):
            return kSecAttrAccessibleAfterFirstUnlock
        case .whenPasscodeSet:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    /// The `SecAccessControlCreateFlags` for a presence requirement.
    static func accessControlFlags(for presence: PresenceRequirement) -> SecAccessControlCreateFlags {
        switch presence {
        case .none:                    return []
        case .userPresence:            return .userPresence
        case .biometry(.currentSet):   return .biometryCurrentSet
        case .biometry(.anyEnrolled):  return .biometryAny
        case .devicePasscode:          return .devicePasscode
        }
    }

    /// Whether the policy opts into iCloud Keychain sync.
    var isSynchronizable: Bool {
        switch protection {
        case .whenUnlocked(.synchronizable), .afterFirstUnlock(.synchronizable):
            return true
        case .whenUnlocked(.thisDeviceOnly), .afterFirstUnlock(.thisDeviceOnly), .whenPasscodeSet:
            return false
        }
    }

    /// The identity query shared by add / fetch / update / delete: class, service, account,
    /// access group, sync flag, and the modern data-protection keychain.
    ///
    /// `kSecUseDataProtectionKeychain` is set on every platform for one consistent semantics: it
    /// is the only keychain on iOS/watchOS/visionOS, and on macOS it is the modern, dialog-free
    /// keychain (the legacy login keychain prompts on data reads). Unsigned macOS CLI/test
    /// binaries lack the required entitlement, so real-keychain tests there are environment-gated
    /// (they run on the iOS Simulator and on signed CI); this is called out in the TestingStrategy.
    func baseQuery() -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        if isSynchronizable {
            query[kSecAttrSynchronizable] = true
        }
        return query
    }

    /// A query scoped to the whole service + access group (no account), for enumeration and
    /// bulk delete. Matches any synchronizability so it sees every item in the namespace.
    func serviceScopeQuery() -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecUseDataProtectionKeychain: true,
            kSecAttrSynchronizable: kSecAttrSynchronizableAny,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        return query
    }

    /// The protection attributes for an add: a plain `kSecAttrAccessible` constant, or — when a
    /// presence requirement is set — a `SecAccessControl`. Throws when the OS rejects the
    /// combination.
    func protectionAttributes() throws(KeychainError) -> [CFString: Any] {
        guard presence != .none else {
            return [kSecAttrAccessible: ItemDescriptor.accessibleValue(for: protection)]
        }
        var error: Unmanaged<CFError>?
        let control = SecAccessControlCreateWithFlags(
            nil,
            ItemDescriptor.accessibleValue(for: protection),
            ItemDescriptor.accessControlFlags(for: presence),
            &error
        )
        guard let control else {
            error?.release()
            throw KeychainError.protectionUnsatisfiable(protection)
        }
        return [kSecAttrAccessControl: control]
    }
}
