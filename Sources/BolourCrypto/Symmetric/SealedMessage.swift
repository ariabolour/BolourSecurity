import Foundation

/// The output of authenticated encryption: nonce ‖ ciphertext ‖ tag, wrapped with a 1-byte
/// format version and a 1-byte suite tag so future suite migrations can decode old ciphertexts
/// unambiguously.
public struct SealedMessage: Sendable, Hashable, Codable {
    /// The current combined-representation format version.
    static let currentVersion: UInt8 = 1

    let suite: CipherSuite
    /// CryptoKit's combined box: nonce ‖ ciphertext ‖ tag.
    let payload: Data

    init(suite: CipherSuite, payload: Data) {
        self.suite = suite
        self.payload = payload
    }

    /// The portable byte form: `[version][suite][nonce ‖ ciphertext ‖ tag]`.
    public var combinedRepresentation: Data {
        var out = Data([SealedMessage.currentVersion, suite.wireByte])
        out.append(payload)
        return out
    }

    /// Parses a combined representation produced by ``combinedRepresentation``.
    public init(combinedRepresentation data: Data) throws(CryptoError) {
        guard data.count >= 2 else { throw CryptoError.malformedMessage }
        let version = data[data.startIndex]
        guard version == SealedMessage.currentVersion else {
            throw CryptoError.unsupportedFormatVersion(version)
        }
        guard let suite = CipherSuite(wireByte: data[data.startIndex + 1]) else {
            throw CryptoError.malformedMessage
        }
        self.suite = suite
        self.payload = data.subdata(in: (data.startIndex + 2)..<data.endIndex)
    }

    // Codable via the combined representation (single value), so the versioned wire form is the
    // canonical serialization everywhere.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)
        do {
            self = try SealedMessage(combinedRepresentation: data)
        } catch {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid SealedMessage")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(combinedRepresentation)
    }
}
