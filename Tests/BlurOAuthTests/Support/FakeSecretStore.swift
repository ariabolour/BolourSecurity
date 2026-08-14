import Foundation
import BlurSecurityCore

/// An in-memory `SecretStore` double — `BlurOAuth` tests never need to touch the real keychain.
actor FakeSecretStore: SecretStore {
    private var storage: [ItemKey: SecureBytes] = [:]

    func store(_ secret: SecureBytes, for key: ItemKey) async throws {
        storage[key] = secret
    }
    func secret(for key: ItemKey) async throws -> SecureBytes? {
        storage[key]
    }
    func removeSecret(for key: ItemKey) async throws {
        storage.removeValue(forKey: key)
    }
}
