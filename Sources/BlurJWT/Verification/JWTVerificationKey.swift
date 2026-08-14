import Foundation
import BlurCrypto
import BlurSecurityCore

/// A key `JWTVerifier` can check a signature against. Every conformer carries its own algorithm
/// — the verifier derives its acceptable-algorithm allowlist from the keys it's given, never
/// from a token's header, which is what makes algorithm confusion unrepresentable.
public protocol JWTVerificationKey: Sendable {
    var keyID: String? { get }
    var jwtAlgorithm: String { get }
    func isValidSignature(_ signature: Data, signingInput: Data) -> Bool
}

/// Wraps a `VerificationKey<P256>` (ECDSA P-256, JWS `alg: ES256`).
public struct ES256VerificationKey: JWTVerificationKey {
    public let keyID: String?
    let key: VerificationKey<P256>

    public init(_ key: VerificationKey<P256>, keyID: String? = nil) {
        self.key = key
        self.keyID = keyID
    }

    public var jwtAlgorithm: String { "ES256" }

    public func isValidSignature(_ signature: Data, signingInput: Data) -> Bool {
        key.isValidSignature(Signature(rawRepresentation: signature), for: signingInput)
    }
}

/// Wraps a `VerificationKey<Ed25519>` (EdDSA, JWS `alg: EdDSA`).
public struct EdDSAVerificationKey: JWTVerificationKey {
    public let keyID: String?
    let key: VerificationKey<Ed25519>

    public init(_ key: VerificationKey<Ed25519>, keyID: String? = nil) {
        self.key = key
        self.keyID = keyID
    }

    public var jwtAlgorithm: String { "EdDSA" }

    public func isValidSignature(_ signature: Data, signingInput: Data) -> Bool {
        key.isValidSignature(Signature(rawRepresentation: signature), for: signingInput)
    }
}

/// Wraps a `SymmetricKey` used as an HMAC-SHA256 key (JWS `alg: HS256`). The same secret both
/// signs and verifies — docs steer new integrations toward ES256/EdDSA, where the verifying
/// party never needs to hold signing-capable material at all.
public struct HS256VerificationKey: JWTVerificationKey {
    public let keyID: String?
    let key: SymmetricKey

    public init(_ key: SymmetricKey, keyID: String? = nil) {
        self.key = key
        self.keyID = keyID
    }

    public var jwtAlgorithm: String { "HS256" }

    public func isValidSignature(_ signature: Data, signingInput: Data) -> Bool {
        // AuthenticationCode has no public initializer from raw bytes (by design — it's meant
        // to be produced only by HMAC.code(for:using:)), so the presented signature is compared
        // against a freshly computed code via SecureBytes' own constant-time `==` instead of
        // HMAC.isValidCode.
        let expected = HMAC<SHA256>.code(for: signingInput, using: key)
        let expectedBytes = expected.withUnsafeBytes { SecureBytes($0) }
        return expectedBytes == SecureBytes(signature)
    }
}
