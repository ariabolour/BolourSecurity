import Foundation
import CryptoKit

/// A digital-signature algorithm. Conformed to by ``P256`` and ``Ed25519``; used as a phantom
/// type so a signature is bound to its algorithm at compile time.
///
/// The underscore-prefixed members are an implementation detail (they operate on raw `Data`
/// representations so no CryptoKit type leaks into the public API) — do not call or conform.
public protocol SignatureAlgorithm: Sendable {
    static func _generatePrivateKeyRepresentation() -> Data
    static func _publicKeyRepresentation(fromPrivateKeyRepresentation priv: Data) throws(CryptoError) -> Data
    static func _signature(for data: Data, privateKeyRepresentation priv: Data) throws(CryptoError) -> Data
    static func _isValidSignature(_ signature: Data, for data: Data, publicKeyRepresentation pub: Data) -> Bool
    static func _validatePublicKeyRepresentation(_ pub: Data) throws(CryptoError)
}

/// NIST P-256 ECDSA.
public enum P256: SignatureAlgorithm {
    public static func _generatePrivateKeyRepresentation() -> Data {
        CryptoKit.P256.Signing.PrivateKey().rawRepresentation
    }
    public static func _publicKeyRepresentation(fromPrivateKeyRepresentation priv: Data) throws(CryptoError) -> Data {
        do { return try CryptoKit.P256.Signing.PrivateKey(rawRepresentation: priv).publicKey.rawRepresentation }
        catch { throw CryptoError.invalidKey }
    }
    public static func _signature(for data: Data, privateKeyRepresentation priv: Data) throws(CryptoError) -> Data {
        do {
            let key = try CryptoKit.P256.Signing.PrivateKey(rawRepresentation: priv)
            return try key.signature(for: data).rawRepresentation
        } catch { throw CryptoError.signingFailed }
    }
    public static func _isValidSignature(_ signature: Data, for data: Data, publicKeyRepresentation pub: Data) -> Bool {
        guard let key = try? CryptoKit.P256.Signing.PublicKey(rawRepresentation: pub),
              let sig = try? CryptoKit.P256.Signing.ECDSASignature(rawRepresentation: signature)
        else { return false }
        return key.isValidSignature(sig, for: data)
    }
    public static func _validatePublicKeyRepresentation(_ pub: Data) throws(CryptoError) {
        do { _ = try CryptoKit.P256.Signing.PublicKey(rawRepresentation: pub) }
        catch { throw CryptoError.invalidKey }
    }
}

/// Edwards-curve Ed25519 (EdDSA).
public enum Ed25519: SignatureAlgorithm {
    public static func _generatePrivateKeyRepresentation() -> Data {
        Curve25519.Signing.PrivateKey().rawRepresentation
    }
    public static func _publicKeyRepresentation(fromPrivateKeyRepresentation priv: Data) throws(CryptoError) -> Data {
        do { return try Curve25519.Signing.PrivateKey(rawRepresentation: priv).publicKey.rawRepresentation }
        catch { throw CryptoError.invalidKey }
    }
    public static func _signature(for data: Data, privateKeyRepresentation priv: Data) throws(CryptoError) -> Data {
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: priv)
            return try key.signature(for: data)
        } catch { throw CryptoError.signingFailed }
    }
    public static func _isValidSignature(_ signature: Data, for data: Data, publicKeyRepresentation pub: Data) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
        return key.isValidSignature(signature, for: data)
    }
    public static func _validatePublicKeyRepresentation(_ pub: Data) throws(CryptoError) {
        do { _ = try Curve25519.Signing.PublicKey(rawRepresentation: pub) }
        catch { throw CryptoError.invalidKey }
    }
}
