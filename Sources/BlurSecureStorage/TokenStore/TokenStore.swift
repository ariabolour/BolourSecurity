import Foundation
import BlurSecurityCore
import BlurKeychain

/// Typed storage for tokens/credentials with expiry semantics — the canonical `SecretStore`
/// conformer `BlurOAuth` consumes through the Core seam.
public struct TokenStore: SecretStore, Sendable {
    private let keychain: Keychain
    private let namespace: ItemKey

    public init(keychain: Keychain = Keychain(), namespace: ItemKey = "blur.tokens") {
        self.keychain = keychain
        self.namespace = namespace
    }

    /// Stores `token` under `key`, replacing any existing value.
    public func store(_ token: StoredToken, for key: ItemKey) async throws(StorageError) {
        do { try await keychain.store(token, for: namespaced(key)) }
        catch { throw StorageError.underlying(error) }
    }

    /// Returns the token stored under `key`, or `nil` for absent OR expired-and-pruned tokens —
    /// callers see one "get a valid token or refresh" decision point, not two.
    public func validToken(
        for key: ItemKey, leeway: Duration = .seconds(30)
    ) async throws(StorageError) -> StoredToken? {
        let namespacedKey = namespaced(key)
        let token: StoredToken?
        do { token = try await keychain.value(StoredToken.self, for: namespacedKey) }
        catch { throw StorageError.underlying(error) }

        guard let token else { return nil }
        if let expiresAt = token.expiresAt, Date().addingTimeInterval(leeway.timeInterval) >= expiresAt {
            do { try await keychain.removeSecret(for: namespacedKey) }
            catch { throw StorageError.underlying(error) }
            return nil
        }
        return token
    }

    /// Removes the token stored under `key`, if any.
    public func removeToken(for key: ItemKey) async throws(StorageError) {
        do {
            try await keychain.removeSecret(for: namespaced(key))
        } catch KeychainError.itemNotFound {
            // Already absent: removing an absent token is not a failure for this API.
        } catch {
            throw StorageError.underlying(error)
        }
    }

    // MARK: - SecretStore (opaque bytes, for consumers that don't need StoredToken's metadata)

    public func store(_ secret: SecureBytes, for key: ItemKey) async throws {
        try await keychain.store(secret, for: namespaced(key))
    }

    public func secret(for key: ItemKey) async throws -> SecureBytes? {
        try await keychain.secret(for: namespaced(key))
    }

    public func removeSecret(for key: ItemKey) async throws {
        try await keychain.removeSecret(for: namespaced(key))
    }

    private func namespaced(_ key: ItemKey) -> ItemKey {
        ItemKey("\(namespace.rawValue).\(key.rawValue)")
    }
}

extension Duration {
    fileprivate var timeInterval: TimeInterval {
        let components = self.components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1e18
    }
}
