import Testing
import Foundation
import BlurCrypto
@testable import BlurJWT

@Suite("JWK parsing")
struct JWKTests {

    @Test("an EC P-256 JWK reconstructs a verification key that validates a real signature")
    func ecJWKRoundTrips() throws {
        let signingKey = SigningKey<P256>.software()
        // X ‖ Y, 64 bytes, no tag byte. Sliced via [UInt8], not Data.subdata(in:) with literal
        // integer bounds: CryptoKit's rawRepresentation is not guaranteed to start at Data index
        // 0 (confirmed empirically — it does not), so a literal `0..<32` range is a real crash,
        // not just a style nit.
        let rawBytes = [UInt8](signingKey.verificationKey.rawRepresentation)
        let x = Data(rawBytes[0..<32])
        let y = Data(rawBytes[32..<64])

        let jwk = JWK(keyType: "EC", curve: "P-256", x: Base64URL.encode(x), y: Base64URL.encode(y), k: nil, keyID: "ec1")
        let verificationKey = try #require(try jwk.verificationKey())
        #expect(verificationKey.jwtAlgorithm == "ES256")
        #expect(verificationKey.keyID == "ec1")

        let message = Data("hello".utf8)
        let signature = try signingKey.signature(for: message).rawRepresentation
        #expect(verificationKey.isValidSignature(signature, signingInput: message))
    }

    @Test("an OKP Ed25519 JWK reconstructs a verification key that validates a real signature")
    func okpJWKRoundTrips() throws {
        let signingKey = SigningKey<Ed25519>.software()
        let x = signingKey.verificationKey.rawRepresentation

        let jwk = JWK(keyType: "OKP", curve: "Ed25519", x: Base64URL.encode(x), y: nil, k: nil, keyID: "okp1")
        let verificationKey = try #require(try jwk.verificationKey())
        #expect(verificationKey.jwtAlgorithm == "EdDSA")

        let message = Data("hello".utf8)
        let signature = try signingKey.signature(for: message).rawRepresentation
        #expect(verificationKey.isValidSignature(signature, signingInput: message))
    }

    @Test("an oct JWK reconstructs an HMAC verification key")
    func octJWKRoundTrips() throws {
        // SymmetricKey has no public accessor for its raw bytes, so this test controls the raw
        // key material directly (as a JWKS parser would receive it over the wire) and confirms a
        // signature made with the SAME bytes, via SymmetricKey(secureBytes:), verifies.
        let rawKeyBytes = SecureRandom.bytes(count: 32)
        let hmacKey = try SymmetricKey(secureBytes: rawKeyBytes)

        let jwk = JWK(keyType: "oct", curve: nil, x: nil, y: nil, k: Base64URL.encode(rawKeyBytes.dangerouslyExportBytes()), keyID: "oct1")
        let verificationKey = try #require(try jwk.verificationKey())
        #expect(verificationKey.jwtAlgorithm == "HS256")

        let message = Data("hello".utf8)
        let signature = HMAC<SHA256>.code(for: message, using: hmacKey).withUnsafeBytes { Data($0) }
        #expect(verificationKey.isValidSignature(signature, signingInput: message))
    }

    @Test("an unsupported key type/curve is silently skipped, not an error")
    func unsupportedKeyTypeSkipped() throws {
        let jwk = JWK(keyType: "RSA", curve: nil, x: nil, y: nil, k: nil, keyID: "rsa1")
        #expect(try jwk.verificationKey() == nil)
    }

    @Test("a JWK Set with a mix of supported and unsupported keys yields only the supported ones")
    func jwkSetFiltersUnsupported() throws {
        let key = SigningKey<P256>.software()
        let rawBytes = [UInt8](key.verificationKey.rawRepresentation)
        let supported = JWK(
            keyType: "EC", curve: "P-256",
            x: Base64URL.encode(Data(rawBytes[0..<32])), y: Base64URL.encode(Data(rawBytes[32..<64])),
            k: nil, keyID: "good"
        )
        let unsupported = JWK(keyType: "RSA", curve: nil, x: nil, y: nil, k: nil, keyID: "bad")
        let set = JWKSet(keys: [supported, unsupported])
        #expect(set.verificationKeys().count == 1)
        #expect(set.verificationKeys()[0].keyID == "good")
    }
}
