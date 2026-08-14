import Foundation
import BlurCrypto

/// The internal seam behind `JWTSigner` — one conformer per supported algorithm, each producing
/// raw JWS signature bytes (already in the form the spec expects; ES256/EdDSA/HS256 all happen
/// to need no DER-style conversion once the underlying key type does its own, as
/// `SecureEnclaveKey` does internally).
protocol JWTSigningImplementation: Sendable {
    var jwtAlgorithm: String { get }
    func sign(_ signingInput: Data) throws(JWTError) -> Data
}

struct ES256SigningImplementation: JWTSigningImplementation {
    let key: SigningKey<P256>
    var jwtAlgorithm: String { "ES256" }
    func sign(_ signingInput: Data) throws(JWTError) -> Data {
        do { return try key.signature(for: signingInput).rawRepresentation }
        catch { throw JWTError.signingFailed(underlying: error) }
    }
}

struct EdDSASigningImplementation: JWTSigningImplementation {
    let key: SigningKey<Ed25519>
    var jwtAlgorithm: String { "EdDSA" }
    func sign(_ signingInput: Data) throws(JWTError) -> Data {
        do { return try key.signature(for: signingInput).rawRepresentation }
        catch { throw JWTError.signingFailed(underlying: error) }
    }
}

struct SecureEnclaveSigningImplementation: JWTSigningImplementation {
    let key: SecureEnclaveKey
    var jwtAlgorithm: String { "ES256" }
    func sign(_ signingInput: Data) throws(JWTError) -> Data {
        do { return try key.signature(for: signingInput).rawRepresentation }
        catch { throw JWTError.signingFailed(underlying: error) }
    }
}

struct HS256SigningImplementation: JWTSigningImplementation {
    let key: SymmetricKey
    var jwtAlgorithm: String { "HS256" }
    func sign(_ signingInput: Data) throws(JWTError) -> Data {
        HMAC<SHA256>.code(for: signingInput, using: key).withUnsafeBytes { Data($0) }
    }
}
