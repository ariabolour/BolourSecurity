import Testing
import Foundation
import BlurKeychain
import BlurSecurityCore

/// Round-trips against the real keychain. Gated on ``KeychainProbe/isAvailable`` so the suite
/// skips cleanly where an unsigned test binary cannot reach the data-protection keychain.
@Suite("Keychain integration", .enabled(if: KeychainProbe.isAvailable))
struct KeychainIntegrationTests {

    /// A fresh, isolated keychain namespace per test, cleaned up after.
    private func makeKeychain(_ label: String = #function) -> Keychain {
        Keychain(service: "BlurSecurityTests.\(label).\(UUID().uuidString)")
    }

    @Test("store, read, contains, remove — the five-minute win")
    func roundTrip() async throws {
        let keychain = makeKeychain()
        let key: ItemKey = "auth.refresh-token"
        let secret = SecureBytes(Array("s3cr3t-token".utf8))

        try await keychain.store(secret, for: key)
        #expect(try await keychain.contains(key))
        #expect(try await keychain.secret(for: key) == secret)

        try await keychain.removeSecret(for: key)
        #expect(try await keychain.contains(key) == false)
        #expect(try await keychain.secret(for: key) == nil)
    }

    @Test("storing again updates in place (last-writer-wins)")
    func updateInPlace() async throws {
        let keychain = makeKeychain()
        let key: ItemKey = "k"
        try await keychain.store(SecureBytes(Array("first".utf8)), for: key)
        try await keychain.store(SecureBytes(Array("second".utf8)), for: key)
        #expect(try await keychain.secret(for: key) == SecureBytes(Array("second".utf8)))
        try await keychain.removeAllSecrets()
    }

    @Test("removing an absent item throws itemNotFound")
    func removeAbsent() async throws {
        let keychain = makeKeychain()
        await #expect(throws: KeychainError.self) {
            try await keychain.removeSecret(for: "does.not.exist")
        }
    }

    @Test("allKeys is isolated per service")
    func allKeysIsolation() async throws {
        let a = makeKeychain("a")
        let b = makeKeychain("b")
        try await a.store(SecureBytes([1]), for: "one")
        try await a.store(SecureBytes([2]), for: "two")
        try await b.store(SecureBytes([3]), for: "three")

        let aKeys = Set(try await a.allKeys().map(\.rawValue))
        let bKeys = Set(try await b.allKeys().map(\.rawValue))
        #expect(aKeys == ["one", "two"])
        #expect(bKeys == ["three"])

        try await a.removeAllSecrets()
        try await b.removeAllSecrets()
        #expect(try await a.allKeys().isEmpty)
    }

    @Test("typed SecretConvertible values round-trip")
    func typedValues() async throws {
        let keychain = makeKeychain()
        let token = Token(value: "abc.def.ghi")
        try await keychain.store(token, for: "jwt")
        let restored: Token? = try await keychain.value(for: "jwt")
        #expect(restored == token)
        try await keychain.removeAllSecrets()
    }

    @Test("usable through the SecretStore Core seam")
    func secretStoreConformance() async throws {
        let store: any SecretStore = makeKeychain()
        try await store.store(SecureBytes([9, 9, 9]), for: "seam")
        #expect(try await store.secret(for: "seam") == SecureBytes([9, 9, 9]))
        try await store.removeSecret(for: "seam")
    }

    @Test("concurrent writes to one key leave a single consistent value")
    func concurrentWrites() async throws {
        let keychain = makeKeychain()
        let key: ItemKey = "storm"
        try await keychain.store(SecureBytes([0]), for: key)
        await withTaskGroup(of: Void.self) { group in
            for value in UInt8(1)...UInt8(16) {
                group.addTask {
                    try? await keychain.store(SecureBytes([value]), for: key)
                }
            }
        }
        // Exactly one item exists and it reads back without error (no duplicate leaked).
        #expect(try await keychain.contains(key))
        #expect(try await keychain.allKeys() == ["storm"])
        try await keychain.removeAllSecrets()
    }

    private struct Token: SecretConvertible, Equatable {
        var value: String
        init(value: String) { self.value = value }
        init(secureBytes: SecureBytes) throws {
            guard let decoded = String(data: secureBytes.dangerouslyExportBytes(), encoding: .utf8) else {
                throw TokenError.notUTF8
            }
            value = decoded
        }
        func secureBytesRepresentation() throws -> SecureBytes { SecureBytes(Array(value.utf8)) }
        enum TokenError: Error { case notUTF8 }
    }
}
