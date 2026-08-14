import Testing
import Foundation
import BlurCrypto
import BlurSecurityCore
@testable import BlurJWT

/// The header never chooses the algorithm — the verifier's key set does. These are the classic
/// real-world JWT vulnerabilities, each proven unrepresentable rather than merely "handled."
@Suite("Algorithm confusion is unrepresentable")
struct AlgorithmConfusionTests {

    private func policy() -> JWTValidationPolicy {
        JWTValidationPolicy(issuer: "https://issuer.example", audience: "aud", requireExpiry: false)
    }

    @Test("alg: none is rejected even though it parses structurally")
    func algNoneRejected() async throws {
        let header = Base64URL.encode(Data("{\"alg\":\"none\"}".utf8))
        let payload = Base64URL.encode(Data("{\"iss\":\"https://issuer.example\",\"aud\":[\"aud\"]}".utf8))
        let token = try UnverifiedJWT(compactSerialization: "\(header).\(payload).")

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(SigningKey<P256>.software().verificationKey)], policy: policy()
        )
        do {
            _ = try await verifier.verify(token, as: RegisteredClaims.self)
            Issue.record("expected algorithmMismatch")
        } catch JWTError.algorithmMismatch(let tokenAlgorithm) {
            #expect(tokenAlgorithm == "none")
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("a public verification key cannot be reused as an HMAC secret to forge an HS256 token")
    func publicKeyReuseAsHMACSecretFails() async throws {
        let signingKey = SigningKey<P256>.software()
        // BlurCrypto.SymmetricKey is fixed at 256 bits; a real RS256/ES256 -> HS256 confusion
        // attack in the wild derives *some* fixed-length secret from the public key material
        // (often just the DER/PEM bytes hashed or truncated to fit). The exact derivation
        // doesn't matter for what this test proves — the verifier has no HS256 key registered
        // at all, so no guessed secret can produce a signature it will accept.
        let guessedSecret = SHA256.digest(of: signingKey.verificationKey.rawRepresentation)

        // The attacker's forged token: HS256, "signed" using a secret derived from the ES256
        // public key.
        let header = Base64URL.encode(Data("{\"alg\":\"HS256\"}".utf8))
        let payload = Base64URL.encode(Data("{\"iss\":\"https://issuer.example\",\"aud\":[\"aud\"],\"sub\":\"admin\"}".utf8))
        let signingInput = Data("\(header).\(payload)".utf8)
        let forgedKey = try SymmetricKey(secureBytes: SecureBytes(guessedSecret.withUnsafeBytes { Data($0) }))
        let forgedSignature = HMAC<SHA256>.code(for: signingInput, using: forgedKey).withUnsafeBytes { Data($0) }
        let forged = "\(header).\(payload).\(Base64URL.encode(forgedSignature))"

        // The verifier only holds the ES256 key — it never had an HS256 key at all, so there is
        // no key whose jwtAlgorithm is "HS256" for the header to match against.
        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(signingKey.verificationKey)], policy: policy()
        )
        do {
            _ = try await verifier.verify(UnverifiedJWT(compactSerialization: forged), as: RegisteredClaims.self)
            Issue.record("expected algorithmMismatch")
        } catch JWTError.algorithmMismatch {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("a token signed with an unrelated key of the SAME algorithm still fails signature verification")
    func wrongKeySameAlgorithmFails() async throws {
        let legitimateKey = SigningKey<P256>.software()
        let attackerKey = SigningKey<P256>.software()
        let signer = JWTSigner(key: attackerKey)
        let signed = try await signer.sign(
            RegisteredClaims(issuer: "https://issuer.example", audience: ["aud"]), expiresIn: .seconds(300)
        )

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(legitimateKey.verificationKey)], policy: policy()
        )
        await #expect(throws: JWTError.self) {
            _ = try await verifier.verify(
                UnverifiedJWT(compactSerialization: signed.compactSerialization), as: RegisteredClaims.self
            )
        }
    }

    @Test("an unknown kid is rejected even when a same-algorithm key would otherwise validate")
    func unknownKidRejected() async throws {
        let key = SigningKey<P256>.software()
        let signer = JWTSigner(key: key, keyID: "real-kid")
        let signed = try await signer.sign(
            RegisteredClaims(issuer: "https://issuer.example", audience: ["aud"]), expiresIn: .seconds(300)
        )

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(key.verificationKey, keyID: "different-kid")], policy: policy()
        )
        do {
            _ = try await verifier.verify(
                UnverifiedJWT(compactSerialization: signed.compactSerialization), as: RegisteredClaims.self
            )
            Issue.record("expected unknownKeyID")
        } catch JWTError.unknownKeyID(let kid) {
            #expect(kid == "real-kid")
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }
}
