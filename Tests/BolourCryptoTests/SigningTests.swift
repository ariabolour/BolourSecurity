import Testing
import Foundation
import CryptoKit
import BolourCrypto

@Suite("Signing")
struct SigningTests {

    @Test("P-256 signs, verifies, rejects tampered data, and interops with CryptoKit")
    func p256() throws {
        let key = SigningKey<BolourCrypto.P256>.software()
        let message = Data("attack at dawn".utf8)
        let signature = try key.signature(for: message)

        #expect(key.verificationKey.isValidSignature(signature, for: message))
        #expect(key.verificationKey.isValidSignature(signature, for: Data("attack at dusk".utf8)) == false)

        // Our output is standard P-256 ECDSA: CryptoKit verifies it directly.
        let ckKey = try CryptoKit.P256.Signing.PublicKey(rawRepresentation: key.verificationKey.rawRepresentation)
        let ckSig = try CryptoKit.P256.Signing.ECDSASignature(rawRepresentation: signature.rawRepresentation)
        #expect(ckKey.isValidSignature(ckSig, for: message))
    }

    @Test("Ed25519 signs, verifies, and interops with CryptoKit")
    func ed25519() throws {
        let key = SigningKey<Ed25519>.software()
        let message = Data("attack at dawn".utf8)
        let signature = try key.signature(for: message)

        #expect(key.verificationKey.isValidSignature(signature, for: message))
        #expect(key.verificationKey.isValidSignature(signature, for: Data("x".utf8)) == false)

        // Our output is standard Ed25519: CryptoKit verifies it directly.
        let ckKey = try Curve25519.Signing.PublicKey(rawRepresentation: key.verificationKey.rawRepresentation)
        #expect(ckKey.isValidSignature(signature.rawRepresentation, for: message))
    }

    @Test("a different key does not verify")
    func crossKey() throws {
        let a = SigningKey<Ed25519>.software()
        let b = SigningKey<Ed25519>.software()
        let message = Data("payload".utf8)
        let signature = try a.signature(for: message)
        #expect(b.verificationKey.isValidSignature(signature, for: message) == false)
    }

    @Test("VerificationKey round-trips through Codable")
    func codable() throws {
        let verificationKey = SigningKey<BolourCrypto.P256>.software().verificationKey
        let encoded = try JSONEncoder().encode(verificationKey)
        let decoded = try JSONDecoder().decode(VerificationKey<BolourCrypto.P256>.self, from: encoded)
        #expect(decoded.rawRepresentation == verificationKey.rawRepresentation)
    }
}
