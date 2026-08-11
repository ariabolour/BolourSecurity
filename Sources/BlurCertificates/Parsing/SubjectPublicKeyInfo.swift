import Foundation

/// A certificate's SubjectPublicKeyInfo: the algorithm identifier plus the raw DER of the whole
/// SPKI structure. The DER is what an SPKI pin hashes (SHA-256), which is why we keep it verbatim.
public struct SubjectPublicKeyInfo: Sendable, Hashable {
    /// The public-key algorithm OID (e.g. "1.2.840.113549.1.1.1" for RSA, "1.2.840.10045.2.1" for EC).
    public let algorithmOID: String
    /// The DER encoding of the entire SubjectPublicKeyInfo SEQUENCE.
    public let derRepresentation: Data

    init(algorithmOID: String, derRepresentation: Data) {
        self.algorithmOID = algorithmOID
        self.derRepresentation = derRepresentation
    }
}
