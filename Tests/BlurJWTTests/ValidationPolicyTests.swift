import Testing
import Foundation
import BlurCrypto
@testable import BlurJWT

@Suite("JWTValidationPolicy enforcement")
struct ValidationPolicyTests {

    private func sign(_ claims: RegisteredClaims, with key: SigningKey<P256>) async throws -> UnverifiedJWT {
        let signed = try await JWTSigner(key: key).sign(claims, expiresIn: .seconds(3600))
        return try UnverifiedJWT(compactSerialization: signed.compactSerialization)
    }

    @Test("clockSkewTolerance beyond the maximum is clamped, never honored")
    func clockSkewClamped() {
        let policy = JWTValidationPolicy(issuer: "i", audience: "a", clockSkewTolerance: .seconds(10_000))
        #expect(policy.clockSkewTolerance == .seconds(300))
    }

    @Test("an expired token is rejected")
    func expiredRejected() async throws {
        let key = SigningKey<P256>.software()
        // Sign with an already-past expiry by hand (the signer only offers expiresIn from now).
        let header = Base64URL.encode(Data("{\"alg\":\"ES256\"}".utf8))
        let past = Date().addingTimeInterval(-3600)
        let payloadJSON = try JSONEncoder.jwtEncoder().encode(
            RegisteredClaims(issuer: "https://issuer.example", audience: ["aud"], expiresAt: past)
        )
        let payload = Base64URL.encode(payloadJSON)
        let signingInput = Data("\(header).\(payload)".utf8)
        let signature = try key.signature(for: signingInput).rawRepresentation
        let token = "\(header).\(payload).\(Base64URL.encode(signature))"

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(key.verificationKey)],
            policy: JWTValidationPolicy(issuer: "https://issuer.example", audience: "aud")
        )
        do {
            _ = try await verifier.verify(try UnverifiedJWT(compactSerialization: token), as: RegisteredClaims.self)
            Issue.record("expected expired")
        } catch JWTError.expired {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("a not-yet-valid token is rejected")
    func notYetValidRejected() async throws {
        let key = SigningKey<P256>.software()
        let header = Base64URL.encode(Data("{\"alg\":\"ES256\"}".utf8))
        let future = Date().addingTimeInterval(3600)
        let payloadJSON = try JSONEncoder.jwtEncoder().encode(
            RegisteredClaims(issuer: "https://issuer.example", audience: ["aud"], notBefore: future)
        )
        let payload = Base64URL.encode(payloadJSON)
        let signingInput = Data("\(header).\(payload)".utf8)
        let signature = try key.signature(for: signingInput).rawRepresentation
        let token = "\(header).\(payload).\(Base64URL.encode(signature))"

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(key.verificationKey)],
            policy: JWTValidationPolicy(issuer: "https://issuer.example", audience: "aud", requireExpiry: false)
        )
        do {
            _ = try await verifier.verify(try UnverifiedJWT(compactSerialization: token), as: RegisteredClaims.self)
            Issue.record("expected notYetValid")
        } catch JWTError.notYetValid {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("issuer mismatch is rejected")
    func issuerMismatchRejected() async throws {
        let key = SigningKey<P256>.software()
        let token = try await sign(RegisteredClaims(issuer: "https://wrong.example", audience: ["aud"], expiresAt: Date().addingTimeInterval(300)), with: key)
        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(key.verificationKey)],
            policy: JWTValidationPolicy(issuer: "https://issuer.example", audience: "aud")
        )
        do {
            _ = try await verifier.verify(token, as: RegisteredClaims.self)
            Issue.record("expected issuerMismatch")
        } catch JWTError.issuerMismatch(let expected) {
            #expect(expected == "https://issuer.example")
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("audience mismatch is rejected")
    func audienceMismatchRejected() async throws {
        let key = SigningKey<P256>.software()
        let token = try await sign(RegisteredClaims(issuer: "https://issuer.example", audience: ["other"], expiresAt: Date().addingTimeInterval(300)), with: key)
        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(key.verificationKey)],
            policy: JWTValidationPolicy(issuer: "https://issuer.example", audience: "aud")
        )
        await #expect(throws: JWTError.self) {
            _ = try await verifier.verify(token, as: RegisteredClaims.self)
        }
    }

    @Test("requireExpiry: true rejects a token with no exp claim at all")
    func missingExpiryRejectedWhenRequired() async throws {
        let key = SigningKey<P256>.software()
        let header = Base64URL.encode(Data("{\"alg\":\"ES256\"}".utf8))
        let payloadJSON = try JSONEncoder.jwtEncoder().encode(
            RegisteredClaims(issuer: "https://issuer.example", audience: ["aud"])
        )
        let payload = Base64URL.encode(payloadJSON)
        let signingInput = Data("\(header).\(payload)".utf8)
        let signature = try key.signature(for: signingInput).rawRepresentation
        let token = "\(header).\(payload).\(Base64URL.encode(signature))"

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(key.verificationKey)],
            policy: JWTValidationPolicy(issuer: "https://issuer.example", audience: "aud", requireExpiry: true)
        )
        do {
            _ = try await verifier.verify(try UnverifiedJWT(compactSerialization: token), as: RegisteredClaims.self)
            Issue.record("expected expired (missing required exp)")
        } catch JWTError.expired {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("requireExpiry: false accepts a token with no exp claim")
    func missingExpiryAcceptedWhenNotRequired() async throws {
        let key = SigningKey<P256>.software()
        let header = Base64URL.encode(Data("{\"alg\":\"ES256\"}".utf8))
        let payloadJSON = try JSONEncoder.jwtEncoder().encode(
            RegisteredClaims(issuer: "https://issuer.example", audience: ["aud"])
        )
        let payload = Base64URL.encode(payloadJSON)
        let signingInput = Data("\(header).\(payload)".utf8)
        let signature = try key.signature(for: signingInput).rawRepresentation
        let token = "\(header).\(payload).\(Base64URL.encode(signature))"

        let verifier = JWTVerifier(
            keys: [ES256VerificationKey(key.verificationKey)],
            policy: JWTValidationPolicy(issuer: "https://issuer.example", audience: "aud", requireExpiry: false)
        )
        _ = try await verifier.verify(try UnverifiedJWT(compactSerialization: token), as: RegisteredClaims.self)
    }

    @Test("a single string audience in the wire form decodes into a one-element array")
    func singleStringAudienceDecodes() throws {
        let json = "{\"iss\":\"i\",\"aud\":\"solo\"}"
        let claims = try ClaimsCoding.makeDecoder().decode(RegisteredClaims.self, from: Data(json.utf8))
        #expect(claims.audience == ["solo"])
    }
}

extension JSONEncoder {
    static func jwtEncoder() -> JSONEncoder { ClaimsCoding.makeEncoder() }
}
