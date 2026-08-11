import Foundation
import BlurSecurityCore

/// A typed, async, value-semantic front end to the generic-password keychain.
///
/// `Keychain` is a *configuration value*, not a service: two instances with the same service,
/// access group, and protection address exactly the same items, so copying one is meaningless
/// and safe. There is no singleton — identity lives in the OS, not the wrapper.
///
/// Its async methods are nonisolated, so awaiting one from the main actor runs the synchronous
/// Keychain Services call on the cooperative thread pool — the main actor never blocks on
/// keychain I/O (which can be slow for iCloud-synchronized items).
///
/// ```swift
/// extension ItemKey { static let refreshToken: ItemKey = "auth.refresh-token" }
///
/// let keychain = Keychain()
/// try await keychain.store(tokenBytes, for: .refreshToken)   // the five-minute win
/// let token = try await keychain.secret(for: .refreshToken)
/// ```
public struct Keychain: Sendable {
    let service: String
    let accessGroup: AccessGroup?
    let protection: ProtectionPolicy
    let logger: (any SecurityEventLogger)?

    /// Creates a keychain configuration.
    ///
    /// - Parameters:
    ///   - service: The service namespace; defaults to the main bundle identifier.
    ///   - accessGroup: The sharing group; defaults to the app's own items.
    ///   - protection: The default protection for stored items; defaults to
    ///     `.whenUnlocked(.thisDeviceOnly)` — the strongest policy that allows foreground use.
    ///   - logger: An optional redacting event logger.
    public init(
        service: String? = nil,
        accessGroup: AccessGroup? = nil,
        protection: ProtectionPolicy = .default,
        logger: (any SecurityEventLogger)? = nil
    ) {
        self.service = service ?? Keychain.defaultService
        self.accessGroup = accessGroup
        self.protection = protection
        self.logger = logger
    }

    static let defaultService: String = Bundle.main.bundleIdentifier ?? "BlurSecurity.keychain"

    // MARK: - Secrets (SecureBytes is the native currency)

    /// Stores `secret` under `key`, replacing any existing value.
    public func store(_ secret: SecureBytes, for key: ItemKey) async throws(KeychainError) {
        try synchronouslyStore(secret, for: key, presence: .none)
        logger?.log(.itemStored)
    }

    /// Stores `secret` under `key` behind a user-presence requirement, replacing any existing value.
    public func store(
        _ secret: SecureBytes, for key: ItemKey, presence: PresenceRequirement
    ) async throws(KeychainError) {
        try synchronouslyStore(secret, for: key, presence: presence)
        logger?.log(.itemStored)
    }

    /// Returns the secret stored under `key`, or `nil` if none exists.
    public func secret(for key: ItemKey) async throws(KeychainError) -> SecureBytes? {
        let bytes = try synchronouslyFetch(for: key, context: nil)
        if bytes != nil { logger?.log(.itemRead) }
        return bytes
    }

    /// Returns the secret stored under `key`, presenting `context` for a presence-gated item.
    public func secret(
        for key: ItemKey, context: (any PresenceAuthenticated)?
    ) async throws(KeychainError) -> SecureBytes? {
        let bytes = try synchronouslyFetch(for: key, context: context)
        if bytes != nil { logger?.log(.itemRead) }
        return bytes
    }

    /// Removes the secret stored under `key`. Throws ``KeychainError/itemNotFound(_:)`` if absent.
    public func removeSecret(for key: ItemKey) async throws(KeychainError) {
        try synchronouslyDelete(for: key)
        logger?.log(.itemRemoved)
    }

    // MARK: - Typed values (any SecretConvertible)

    /// Stores a `SecretConvertible` value under `key`.
    public func store<Value: SecretConvertible>(
        _ value: Value, for key: ItemKey
    ) async throws(KeychainError) {
        try await store(secureBytes(from: value), for: key)
    }

    /// Stores a `SecretConvertible` value under `key` behind a user-presence requirement.
    public func store<Value: SecretConvertible>(
        _ value: Value, for key: ItemKey, presence: PresenceRequirement
    ) async throws(KeychainError) {
        try await store(secureBytes(from: value), for: key, presence: presence)
    }

    /// Reads a `SecretConvertible` value stored under `key`, or `nil` if none exists.
    public func value<Value: SecretConvertible>(
        _ type: Value.Type = Value.self, for key: ItemKey
    ) async throws(KeychainError) -> Value? {
        guard let bytes = try await secret(for: key) else { return nil }
        return try Self.decode(Value.self, from: bytes)
    }

    /// Reads a `SecretConvertible` value stored under `key`, presenting `context` for a
    /// presence-gated item.
    public func value<Value: SecretConvertible>(
        _ type: Value.Type = Value.self, for key: ItemKey, context: (any PresenceAuthenticated)?
    ) async throws(KeychainError) -> Value? {
        guard let bytes = try await secret(for: key, context: context) else { return nil }
        return try Self.decode(Value.self, from: bytes)
    }

    // MARK: - Introspection & maintenance

    /// Whether an item exists for `key` (without decrypting its data).
    public func contains(_ key: ItemKey) async throws(KeychainError) -> Bool {
        try synchronouslyContains(key)
    }

    /// Every key in this keychain's service and access group.
    public func allKeys() async throws(KeychainError) -> [ItemKey] {
        try synchronouslyAllKeys()
    }

    /// Removes every item in this keychain's service and access group. Named to read destructive.
    public func removeAllSecrets() async throws(KeychainError) {
        try synchronouslyRemoveAll()
        logger?.log(.itemRemoved)
    }

    // MARK: - Conversion helpers

    private func secureBytes<Value: SecretConvertible>(
        from value: Value
    ) throws(KeychainError) -> SecureBytes {
        do { return try value.secureBytesRepresentation() }
        catch { throw KeychainError.unexpectedItemShape }
    }

    private static func decode<Value: SecretConvertible>(
        _ type: Value.Type, from bytes: SecureBytes
    ) throws(KeychainError) -> Value {
        do { return try Value(secureBytes: bytes) }
        catch { throw KeychainError.unexpectedItemShape }
    }
}

// The Core seam other modules consume. Our typed-throws methods witness the untyped requirements.
extension Keychain: SecretStore {}
