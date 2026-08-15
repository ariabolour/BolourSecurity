import Foundation

/// The result of one-time key attestation — the material a server verifies against Apple's
/// App Attest root CA.
public struct Attestation: Sendable {
    public let keyID: String
    /// The CBOR attestation object; opaque here, parsed server-side.
    public let attestationObject: Data
}
