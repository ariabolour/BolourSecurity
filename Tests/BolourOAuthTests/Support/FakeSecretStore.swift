import Foundation
import BolourSecurityCore

/// An in-memory `SecretStore` double — `BolourOAuth` tests never need to touch the real keychain.
actor FakeSecretStore: SecretStore {
    private var storage: [ItemKey: SecureBytes] = [:]

    /// When set, `store(_:for:)` throws this instead of writing — lets a test simulate a
    /// Keychain-write failure (e.g. mid-rotation) without touching the real keychain. Thrown
    /// *before* `storage` is touched, matching the real `SecItemUpdate`/`SecItemAdd` contract:
    /// a failed write never partially applies.
    private var storeFailure: (any Error)?

    func setStoreFailure(_ error: (any Error)?) {
        storeFailure = error
    }

    func store(_ secret: SecureBytes, for key: ItemKey) async throws {
        if let storeFailure { throw storeFailure }
        storage[key] = secret
    }
    func secret(for key: ItemKey) async throws -> SecureBytes? {
        storage[key]
    }
    func removeSecret(for key: ItemKey) async throws {
        storage.removeValue(forKey: key)
    }
}
