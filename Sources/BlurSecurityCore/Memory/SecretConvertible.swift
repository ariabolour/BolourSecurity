/// A type that can be represented as, and reconstructed from, secret bytes.
///
/// Conform app-owned secret types (tokens, credentials, keys) so they can be stored through
/// the ecosystem's secret-bearing APIs without ever exposing a plaintext `String` or `Data`
/// at the call site. `BlurKeychain` provides a `Codable`-backed adapter for structured
/// secrets built on this protocol.
public protocol SecretConvertible: Sendable {
    /// Reconstructs the value from its secret-bytes representation.
    init(secureBytes: SecureBytes) throws
    /// Produces the value's secret-bytes representation.
    func secureBytesRepresentation() throws -> SecureBytes
}
