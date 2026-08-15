import Foundation
import BolourSecurityCore

/// The private half of a signing key, bound at compile time to its algorithm `A`.
///
/// `software()` is the visible, greppable choice of a software-held key; hardware-backed keys
/// (Secure Enclave) are a separate type arriving in a later release.
///
/// ```swift
/// let key = SigningKey<Ed25519>.software()
/// let signature = try key.signature(for: message)
/// let ok = key.verificationKey.isValidSignature(signature, for: message)
/// ```
public struct SigningKey<A: SignatureAlgorithm>: Sendable {
    private let privateKeyRepresentation: SecureBytes
    private let publicKeyRepresentation: Data

    private init(privateKeyRepresentation priv: Data) throws(CryptoError) {
        self.publicKeyRepresentation = try A._publicKeyRepresentation(fromPrivateKeyRepresentation: priv)
        self.privateKeyRepresentation = SecureBytes(priv)
    }

    /// A freshly generated software key.
    ///
    /// - Note: **Deliberate `try!`, not an oversight.** `A._generatePrivateKeyRepresentation()`
    ///   produces a representation from `A`'s own generator; `A._publicKeyRepresentation`
    ///   deriving from *that same representation* cannot fail by construction — there is no
    ///   external input, no I/O, and no hardware dependency on this path. The invariant is
    ///   local to this one call site (unlike, say, `SecureRandom`'s fail-stop `precondition`s,
    ///   which guard a real OS-level failure mode); if a future `SignatureAlgorithm` conformance
    ///   ever makes that untrue, this is the one place that needs to change.
    public static func software() -> SigningKey {
        try! SigningKey(privateKeyRepresentation: A._generatePrivateKeyRepresentation())
    }

    /// The public key that verifies this key's signatures.
    public var verificationKey: VerificationKey<A> {
        VerificationKey(representation: publicKeyRepresentation)
    }

    /// Signs `data`.
    public func signature(for data: some DataProtocol) throws(CryptoError) -> Signature<A> {
        let priv = privateKeyRepresentation.dangerouslyExportBytes()
        let bytes = try A._signature(for: Data(data), privateKeyRepresentation: priv)
        return Signature(representation: bytes)
    }
}
