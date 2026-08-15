import Foundation
import Security
import BolourSecurityCore

/// The synchronous Keychain Services operations that back both the async public API and the
/// ``KeychainStored`` property wrapper. All `SecItem*` calls live here, behind ``ItemDescriptor``.
extension Keychain {

    func makeDescriptor(for key: ItemKey, presence: PresenceRequirement = .none) -> ItemDescriptor {
        ItemDescriptor(
            service: service, key: key, accessGroup: accessGroup?.rawValue,
            protection: protection, presence: presence
        )
    }

    func synchronouslyStore(
        _ secret: SecureBytes, for key: ItemKey, presence: PresenceRequirement
    ) throws(KeychainError) {
        let descriptor = makeDescriptor(for: key, presence: presence)
        let protectionAttributes = try descriptor.protectionAttributes()
        let data = secret.dangerouslyExportBytes()

        var addQuery = descriptor.baseQuery()
        for (attribute, value) in protectionAttributes { addQuery[attribute] = value }
        addQuery[kSecValueData] = data

        var status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // Last-writer-wins: update the existing item's data in place.
            let updateAttributes: [CFString: Any] = [kSecValueData: data]
            status = SecItemUpdate(descriptor.baseQuery() as CFDictionary, updateAttributes as CFDictionary)
        }
        guard status == errSecSuccess else {
            throw Keychain.map(status, descriptor: descriptor)
        }
    }

    func synchronouslyFetch(
        for key: ItemKey, context: (any PresenceAuthenticated)?
    ) throws(KeychainError) -> SecureBytes? {
        let descriptor = makeDescriptor(for: key)
        var query = descriptor.baseQuery()
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        if let contextObject = context?.authenticationContext {
            query[kSecUseAuthenticationContext] = contextObject
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { throw KeychainError.unexpectedItemShape }
            return SecureBytes(data)
        case errSecItemNotFound:
            return nil
        case errSecInteractionNotAllowed:
            if context == nil { throw KeychainError.authenticationRequired(key) }
            throw KeychainError.interactionNotAllowed
        case errSecAuthFailed:
            if context == nil { throw KeychainError.authenticationRequired(key) }
            throw KeychainError.authenticationFailed(underlying: status)
        default:
            throw Keychain.map(status, descriptor: descriptor)
        }
    }

    func synchronouslyDelete(for key: ItemKey) throws(KeychainError) {
        let descriptor = makeDescriptor(for: key)
        let status = SecItemDelete(descriptor.baseQuery() as CFDictionary)
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw KeychainError.itemNotFound(key)
        default:
            throw Keychain.map(status, descriptor: descriptor)
        }
    }

    func synchronouslyContains(_ key: ItemKey) throws(KeychainError) -> Bool {
        let descriptor = makeDescriptor(for: key)
        var query = descriptor.baseQuery()
        query[kSecReturnData] = false
        query[kSecMatchLimit] = kSecMatchLimitOne
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:      return true
        case errSecItemNotFound: return false
        default:                 throw Keychain.map(status, descriptor: descriptor)
        }
    }

    func synchronouslyAllKeys() throws(KeychainError) -> [ItemKey] {
        var query = makeDescriptor(for: "").serviceScopeQuery()
        query[kSecReturnAttributes] = true
        query[kSecMatchLimit] = kSecMatchLimitAll

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else { throw KeychainError.unexpectedItemShape }
            return items.compactMap { ($0[kSecAttrAccount as String] as? String).map { ItemKey($0) } }
        case errSecItemNotFound:
            return []
        default:
            throw Keychain.map(status, descriptor: makeDescriptor(for: ""))
        }
    }

    func synchronouslyRemoveAll() throws(KeychainError) {
        let query = makeDescriptor(for: "").serviceScopeQuery()
        let status = SecItemDelete(query as CFDictionary)
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw Keychain.map(status, descriptor: makeDescriptor(for: ""))
        }
    }

    /// Translates an `OSStatus` into the `KeychainError` case that teaches, using the descriptor
    /// for context (the key name, and the access group for entitlement failures).
    static func map(_ status: OSStatus, descriptor: ItemDescriptor) -> KeychainError {
        let key = ItemKey(descriptor.account)
        switch status {
        case errSecItemNotFound:      return .itemNotFound(key)
        case errSecDuplicateItem:     return .duplicateItem(key)
        case errSecAuthFailed:        return .authenticationFailed(underlying: status)
        case errSecInteractionNotAllowed: return .interactionNotAllowed
        case errSecMissingEntitlement:
            if let group = descriptor.accessGroup { return .accessGroupDenied(AccessGroup(group)) }
            return .underlying(status)
        default:
            return .underlying(status)
        }
    }
}
