import Foundation
import BlurCrypto
import BlurSecurityCore

/// A JSON Web Key Set (RFC 7517).
struct JWKSet: Decodable {
    let keys: [JWK]
}

/// One JSON Web Key — only the fields this module's curated algorithm set (ES256, EdDSA, HS256)
/// needs to reconstruct a verification key.
struct JWK: Decodable {
    let keyType: String
    let curve: String?
    let x: String?
    let y: String?
    let k: String?
    let keyID: String?

    enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case curve = "crv"
        case x, y, k
        case keyID = "kid"
    }

    /// Reconstructs the verification key this entry describes, or `nil` for a key type/curve
    /// this module doesn't support (JWK Sets commonly carry keys for algorithms a given
    /// consumer never uses — those are silently skipped, not errors).
    func verificationKey() throws(JWTError) -> (any JWTVerificationKey)? {
        switch (keyType, curve) {
        case ("EC", "P-256"):
            guard let x, let y, let xData = Base64URL.decode(x), let yData = Base64URL.decode(y) else {
                return nil
            }
            // CryptoKit's P256 rawRepresentation (what VerificationKey<P256> validates against)
            // is the compact X ‖ Y form with no leading tag byte — NOT the X9.63 0x04 ‖ X ‖ Y
            // form some other ecosystems use. Confirmed empirically via a standalone probe.
            var raw = xData
            raw.append(yData)
            do {
                return ES256VerificationKey(try VerificationKey<P256>(rawRepresentation: raw), keyID: keyID)
            } catch {
                return nil
            }
        case ("OKP", "Ed25519"):
            guard let x, let xData = Base64URL.decode(x) else { return nil }
            do {
                return EdDSAVerificationKey(try VerificationKey<Ed25519>(rawRepresentation: xData), keyID: keyID)
            } catch {
                return nil
            }
        case ("oct", _):
            guard let k, let kData = Base64URL.decode(k) else { return nil }
            do {
                return HS256VerificationKey(try SymmetricKey(secureBytes: SecureBytes(kData)), keyID: keyID)
            } catch {
                return nil
            }
        default:
            return nil
        }
    }
}

extension JWKSet {
    /// Every entry this module knows how to turn into a verification key. Unsupported entries
    /// (algorithms/curves outside the curated set) are dropped rather than failing the whole set.
    func verificationKeys() -> [any JWTVerificationKey] {
        keys.compactMap { try? $0.verificationKey() }
    }
}
