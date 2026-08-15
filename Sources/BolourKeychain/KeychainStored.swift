import BolourSecurityCore

/// A convenience-tier property wrapper for a keychain-backed value.
///
/// `@KeychainStored` offers *synchronous* access backed by Keychain Services' synchronous engine.
/// It is deliberately for non-presence-gated items only: because property access cannot be
/// `async` or `throws`, it swallows errors (a failed read reads as `nil`) and cannot present an
/// authenticated context. Presence-gated items must use the async ``Keychain`` API. The projected
/// value (`$property`) is the backing ``Keychain`` for when you need that richer API.
///
/// ```swift
/// struct Session {
///     @KeychainStored("auth.refresh-token") var refreshToken: TokenString?
/// }
/// ```
@propertyWrapper
public struct KeychainStored<Value: SecretConvertible & Sendable>: Sendable {
    private let key: ItemKey
    private let keychain: Keychain

    /// Binds the wrapper to `key` in `keychain`.
    public init(_ key: ItemKey, keychain: Keychain = Keychain()) {
        self.key = key
        self.keychain = keychain
    }

    /// The stored value, or `nil` if absent or unreadable. Setting `nil` removes the item.
    public var wrappedValue: Value? {
        get {
            guard let bytes = (try? keychain.synchronouslyFetch(for: key, context: nil)) ?? nil else {
                return nil
            }
            return try? Value(secureBytes: bytes)
        }
        nonmutating set {
            if let newValue {
                guard let bytes = try? newValue.secureBytesRepresentation() else { return }
                try? keychain.synchronouslyStore(bytes, for: key, presence: .none)
            } else {
                try? keychain.synchronouslyDelete(for: key)
            }
        }
    }

    /// The backing ``Keychain``, for reaching the full async API via `$property`.
    public var projectedValue: Keychain { keychain }
}
