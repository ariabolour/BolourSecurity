import Foundation

/// A digital signature, bound at compile time to its algorithm `A`.
public struct Signature<A: SignatureAlgorithm>: Sendable, Hashable, Codable {
    let representation: Data

    init(representation: Data) { self.representation = representation }

    /// The raw signature bytes.
    public var rawRepresentation: Data { representation }

    /// Wraps raw signature bytes.
    public init(rawRepresentation: Data) { self.representation = rawRepresentation }

    public init(from decoder: Decoder) throws {
        representation = try decoder.singleValueContainer().decode(Data.self)
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(representation)
    }
}
