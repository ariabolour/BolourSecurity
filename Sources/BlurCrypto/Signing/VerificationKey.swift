import Foundation

/// The public half of a signing key, bound at compile time to its algorithm `A`.
public struct VerificationKey<A: SignatureAlgorithm>: Sendable, Hashable, Codable {
    let representation: Data

    init(representation: Data) { self.representation = representation }

    /// Reconstructs a verification key from raw public-key bytes obtained out of band (e.g. a
    /// JWK's coordinates, or another system's key export) — the inverse of ``rawRepresentation``.
    public init(rawRepresentation: Data) throws(CryptoError) {
        try A._validatePublicKeyRepresentation(rawRepresentation)
        self.representation = rawRepresentation
    }

    /// The raw public-key bytes.
    public var rawRepresentation: Data { representation }

    /// Whether `signature` is a valid `A`-signature over `data` for this key.
    public func isValidSignature(_ signature: Signature<A>, for data: some DataProtocol) -> Bool {
        A._isValidSignature(signature.rawRepresentation, for: Data(data), publicKeyRepresentation: representation)
    }

    public init(from decoder: Decoder) throws {
        let representation = try decoder.singleValueContainer().decode(Data.self)
        do { try A._validatePublicKeyRepresentation(representation) }
        catch {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid public key representation")
            )
        }
        self.representation = representation
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(representation)
    }
}
