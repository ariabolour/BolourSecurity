import Testing
import Foundation
@testable import BlurSecureStorage
import BlurKeychain
import BlurSecurityCore

/// Round-trips against the real keychain. Gated on ``KeychainProbe/isAvailable`` — the same
/// constraint `BlurKeychainTests` documents (live SecItem round-trips can't run in hostless
/// `swift test` bundles).
@Suite("TokenStore", .enabled(if: KeychainProbe.isAvailable))
struct TokenStoreTests {

    private func makeStore() -> TokenStore {
        TokenStore(
            keychain: Keychain(service: "BlurSecureStorageTests.tokens"),
            namespace: ItemKey("test.\(UUID().uuidString)")
        )
    }

    @Test("store then validToken round-trips a non-expiring token")
    func roundTrip() async throws {
        let store = makeStore()
        let key: ItemKey = "session"
        let token = StoredToken(value: SecureBytes(Array("access-token".utf8)), expiresAt: nil)
        try await store.store(token, for: key)
        let fetched = try await store.validToken(for: key)
        #expect(fetched?.value == token.value)
        try await store.removeToken(for: key)
    }

    @Test("validToken returns nil, and prunes the item, once the token has expired")
    func expiredIsPrunedAndNil() async throws {
        let store = makeStore()
        let key: ItemKey = "expiring"
        let token = StoredToken(value: SecureBytes([1]), expiresAt: Date(timeIntervalSinceNow: -1))
        try await store.store(token, for: key)
        let fetched = try await store.validToken(for: key)
        #expect(fetched == nil)
        // Pruned: a second read also sees nothing (not just filtered on this one call).
        #expect(try await store.validToken(for: key) == nil)
    }

    @Test("leeway treats a token as expired slightly before its literal expiresAt")
    func leewayAppliesEarly() async throws {
        let store = makeStore()
        let key: ItemKey = "leeway"
        let token = StoredToken(value: SecureBytes([1]), expiresAt: Date(timeIntervalSinceNow: 10))
        try await store.store(token, for: key)
        // Still valid with no leeway...
        #expect(try await store.validToken(for: key, leeway: .zero) != nil)
        try await store.store(token, for: key)
        // ...but treated as expired with a leeway that reaches past expiresAt.
        #expect(try await store.validToken(for: key, leeway: .seconds(20)) == nil)
    }

    @Test("validToken for an absent key returns nil without throwing")
    func absentReturnsNil() async throws {
        let store = makeStore()
        #expect(try await store.validToken(for: "never-stored") == nil)
    }

    @Test("removeToken for an absent key does not throw")
    func removeAbsentDoesNotThrow() async throws {
        let store = makeStore()
        try await store.removeToken(for: "never-stored")
    }

    @Test("conforms to SecretStore via the opaque-bytes surface")
    func secretStoreConformance() async throws {
        let store = makeStore()
        let key: ItemKey = "opaque"
        let bytes = SecureBytes(Array("opaque-secret".utf8))
        try await store.store(bytes, for: key)
        #expect(try await store.secret(for: key) == bytes)
        try await store.removeSecret(for: key)
        #expect(try await store.secret(for: key) == nil)
    }
}
