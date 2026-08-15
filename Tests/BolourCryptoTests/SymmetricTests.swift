import Testing
import Foundation
import BolourCrypto

@Suite("Symmetric encryption")
struct SymmetricTests {

    @Test("AES-256-GCM round-trips")
    func aesRoundTrip() throws {
        let key = SymmetricKey.random()
        let plaintext = Data("the launch code is 0000".utf8)
        let sealed = try key.seal(plaintext)
        #expect(try key.open(sealed) == plaintext)
    }

    @Test("ChaCha20-Poly1305 round-trips")
    func chachaRoundTrip() throws {
        let key = SymmetricKey.random(.chaChaPoly)
        let plaintext = Data("the launch code is 0000".utf8)
        let sealed = try key.seal(plaintext)
        #expect(try key.open(sealed) == plaintext)
    }

    @Test("a single-bit tamper fails to open")
    func tamperFails() throws {
        let key = SymmetricKey.random()
        let sealed = try key.seal(Data("secret".utf8))
        var bytes = sealed.combinedRepresentation
        bytes[bytes.count - 1] ^= 0x01           // flip a tag bit
        let tampered = try SealedMessage(combinedRepresentation: bytes)
        #expect(throws: CryptoError.self) { _ = try key.open(tampered) }
    }

    @Test("associated data must match")
    func associatedData() throws {
        let key = SymmetricKey.random()
        let aad = Data("format-v1".utf8)
        let sealed = try key.seal(Data("m".utf8), authenticating: aad)
        #expect(try key.open(sealed, authenticating: aad) == Data("m".utf8))
        #expect(throws: CryptoError.self) { _ = try key.open(sealed) }
        #expect(throws: CryptoError.self) { _ = try key.open(sealed, authenticating: Data("format-v2".utf8)) }
    }

    @Test("opening with the wrong suite is a typed mismatch")
    func suiteMismatch() throws {
        let aesKey = SymmetricKey.random(.aes256GCM)
        let chaKey = SymmetricKey.random(.chaChaPoly)
        let sealed = try aesKey.seal(Data("m".utf8))
        #expect(throws: CryptoError.self) { _ = try chaKey.open(sealed) }
    }

    @Test("the combined representation is versioned and re-parses")
    func versionedRepresentation() throws {
        let key = SymmetricKey.random()
        let sealed = try key.seal(Data("hello".utf8))
        let combined = sealed.combinedRepresentation
        #expect(combined.first == 1)                                  // format version
        #expect(combined[combined.startIndex + 1] == 0)               // AES-GCM wire tag
        let reparsed = try SealedMessage(combinedRepresentation: combined)
        #expect(try key.open(reparsed) == Data("hello".utf8))
    }

    @Test("SealedMessage is Codable through its wire form")
    func codable() throws {
        let key = SymmetricKey.random()
        let sealed = try key.seal(Data("hello".utf8))
        let json = try JSONEncoder().encode(sealed)
        let decoded = try JSONDecoder().decode(SealedMessage.self, from: json)
        #expect(try key.open(decoded) == Data("hello".utf8))
    }

    @Test("malformed representations throw, never crash")
    func malformed() {
        #expect(throws: CryptoError.self) { _ = try SealedMessage(combinedRepresentation: Data([0x01])) }
        #expect(throws: CryptoError.self) { _ = try SealedMessage(combinedRepresentation: Data([0x02, 0x00, 0x00])) }
        #expect(throws: CryptoError.self) { _ = try SealedMessage(combinedRepresentation: Data([0x01, 0x09, 0x00])) }
    }
}
