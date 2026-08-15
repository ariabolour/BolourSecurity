import Testing
import Foundation
@testable import BolourCrypto

/// Real Secure Enclave round-trips. Gated on ``SecureEnclaveProbe/isAvailable`` — same
/// constraint as `BolourKeychainTests`' real-keychain suite.
///
/// Tagged `.requiresDevice` per `docs/IntegrationTesting.md` — Tier 3 (device-required).
@Suite("SecureEnclaveKey", .enabled(if: SecureEnclaveProbe.isAvailable), .tags(.requiresDevice))
struct SecureEnclaveKeyTests {

    private func uniqueTag() -> String { "BolourCryptoTests.se-key.\(UUID().uuidString)" }

    @Test("create, sign, and verify round-trip")
    func createSignVerify() throws {
        let tag = uniqueTag()
        let key = try SecureEnclaveKey.create(tag: tag)
        defer { try? key.destroy() }

        let message = Data("sign me".utf8)
        let signature = try key.signature(for: message)
        #expect(try key.verificationKey.isValidSignature(signature, for: message))
        #expect(!(try key.verificationKey.isValidSignature(signature, for: Data("not it".utf8))))
    }

    @Test("load retrieves the same key material a second time")
    func loadRetrievesSameKey() throws {
        let tag = uniqueTag()
        let created = try SecureEnclaveKey.create(tag: tag)
        defer { try? created.destroy() }

        let loaded = try #require(try SecureEnclaveKey.load(tag: tag))
        let message = Data("consistent identity".utf8)
        let signature = try loaded.signature(for: message)
        #expect(try created.verificationKey.isValidSignature(signature, for: message))
        #expect(try created.verificationKey.rawRepresentation == loaded.verificationKey.rawRepresentation)
    }

    @Test("load for a tag that was never created returns nil")
    func loadMissingReturnsNil() throws {
        #expect(try SecureEnclaveKey.load(tag: uniqueTag()) == nil)
    }

    @Test("destroy removes the key so a subsequent load returns nil")
    func destroyRemovesKey() throws {
        let tag = uniqueTag()
        let key = try SecureEnclaveKey.create(tag: tag)
        try key.destroy()
        #expect(try SecureEnclaveKey.load(tag: tag) == nil)
    }
}
