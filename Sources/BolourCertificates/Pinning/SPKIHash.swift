import Foundation
import BolourCrypto

/// SHA-256 of the DER-encoded SubjectPublicKeyInfo — the HPKP/industry pin convention.
///
/// SPKI (not leaf-certificate) pinning survives key-preserving certificate renewals, which is why
/// the pinning API speaks only this type.
public struct SPKIHash: Sendable, Hashable, Codable {
    private let bytes: Data   // 32 bytes

    /// Computes the pin for a certificate's public key.
    public init(of certificate: Certificate) {
        let digest = SHA256.digest(of: certificate.publicKeyInfo.derRepresentation)
        self.bytes = digest.withUnsafeBytes { Data($0) }
    }

    /// Parses a base64-encoded pin (as produced by `openssl` or ``base64EncodedString``).
    public init(base64Encoded string: String) throws(CertificateError) {
        guard let data = Data(base64Encoded: string), data.count == 32 else {
            throw CertificateError.malformedEncoding(detail: .invalidPinEncoding)
        }
        self.bytes = data
    }

    /// The base64 form used in configuration and interchange.
    public var base64EncodedString: String { bytes.base64EncodedString() }

    public init(from decoder: Decoder) throws {
        let string = try decoder.singleValueContainer().decode(String.self)
        guard let data = Data(base64Encoded: string), data.count == 32 else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid SPKI hash")
            )
        }
        self.bytes = data
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64EncodedString)
    }
}
