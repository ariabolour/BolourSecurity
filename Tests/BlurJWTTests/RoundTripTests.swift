import Testing
import Foundation
import BlurCrypto
@testable import BlurJWT

@Suite("Sign then verify round trip")
struct RoundTripTests {
    struct SessionClaims: JWTClaims, Equatable {
        let userID: String
        let roles: [String]
    }

    private func policy() -> JWTValidationPolicy {
        JWTValidationPolicy(issuer: "https://issuer.example", audience: "com.example.app")
    }

    private func claims(userID: String = "u1") -> RegisteredClaims {
        RegisteredClaims(issuer: "https://issuer.example", audience: ["com.example.app"])
    }

    @Test("ES256 sign then verify round-trips claims")
    func es256RoundTrip() async throws {
        let signingKey = SigningKey<P256>.software()
        let signer = JWTSigner(key: signingKey, keyID: "k1")

        // Registered + app-defined claims combined into one payload, mirroring how an app would
        // declare its own claims type.
        struct Combined: JWTClaims {
            var iss: String?; var aud: [String]?; var userID: String; var roles: [String]
            enum CodingKeys: String, CodingKey { case iss, aud, userID, roles }
        }
        let signed = try await signer.sign(
            Combined(iss: "https://issuer.example", aud: ["com.example.app"], userID: "u1", roles: ["admin"]),
            expiresIn: .seconds(300)
        )

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(signingKey.verificationKey, keyID: "k1")],
            policy: policy()
        )
        let unverified = try UnverifiedJWT(compactSerialization: signed.compactSerialization)
        let verified = try await verifier.verify(unverified, as: Combined.self)
        #expect(verified.claims.userID == "u1")
        #expect(verified.claims.roles == ["admin"])
        #expect(verified.registered.issuer == "https://issuer.example")
        #expect(verified.registered.expiresAt != nil)
    }

    @Test("EdDSA sign then verify round-trips claims")
    func eddsaRoundTrip() async throws {
        let signingKey = SigningKey<Ed25519>.software()
        let signer = JWTSigner(key: signingKey, keyID: "k2")
        struct Combined: JWTClaims {
            var iss: String?; var aud: [String]?; var userID: String
            enum CodingKeys: String, CodingKey { case iss, aud, userID }
        }
        let signed = try await signer.sign(
            Combined(iss: "https://issuer.example", aud: ["com.example.app"], userID: "u2"),
            expiresIn: .seconds(300)
        )
        let verifier = JWTVerifier(
            keys: [EdDSAVerificationKey(signingKey.verificationKey, keyID: "k2")],
            policy: policy()
        )
        let verified = try await verifier.verify(
            UnverifiedJWT(compactSerialization: signed.compactSerialization), as: Combined.self
        )
        #expect(verified.claims.userID == "u2")
    }

    @Test("HS256 sign then verify round-trips claims")
    func hs256RoundTrip() async throws {
        let key = SymmetricKey.random()
        let signer = JWTSigner(hmacKey: key, keyID: "k3")
        struct Combined: JWTClaims {
            var iss: String?; var aud: [String]?; var userID: String
            enum CodingKeys: String, CodingKey { case iss, aud, userID }
        }
        let signed = try await signer.sign(
            Combined(iss: "https://issuer.example", aud: ["com.example.app"], userID: "u3"),
            expiresIn: .seconds(300)
        )
        let verifier = JWTVerifier(keys: [HS256VerificationKey(key, keyID: "k3")], policy: policy())
        let verified = try await verifier.verify(
            UnverifiedJWT(compactSerialization: signed.compactSerialization), as: Combined.self
        )
        #expect(verified.claims.userID == "u3")
    }

    @Test("a tampered payload fails signature verification")
    func tamperedPayloadFails() async throws {
        let signingKey = SigningKey<P256>.software()
        let signer = JWTSigner(key: signingKey, keyID: "k1")
        let signed = try await signer.sign(claims(), expiresIn: .seconds(300))

        let parts = signed.compactSerialization.split(separator: ".")
        var payloadData = Base64URL.decode(parts[1])!
        payloadData[0] ^= 0xFF
        let tampered = "\(parts[0]).\(Base64URL.encode(payloadData)).\(parts[2])"

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(signingKey.verificationKey, keyID: "k1")], policy: policy()
        )
        await #expect(throws: JWTError.self) {
            _ = try await verifier.verify(UnverifiedJWT(compactSerialization: tampered), as: RegisteredClaims.self)
        }
    }
}
