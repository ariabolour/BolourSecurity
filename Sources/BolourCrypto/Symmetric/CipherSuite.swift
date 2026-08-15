/// An authenticated cipher suite. There are no unauthenticated modes — by design, CBC/CTR/ECB
/// have no spelling here.
public enum CipherSuite: Sendable, Hashable, CustomStringConvertible {
    /// AES-256 in Galois/Counter Mode. The default.
    case aes256GCM
    /// ChaCha20-Poly1305.
    case chaChaPoly

    /// The 1-byte wire tag used in a ``SealedMessage``'s combined representation.
    var wireByte: UInt8 {
        switch self {
        case .aes256GCM: return 0
        case .chaChaPoly: return 1
        }
    }

    init?(wireByte: UInt8) {
        switch wireByte {
        case 0: self = .aes256GCM
        case 1: self = .chaChaPoly
        default: return nil
        }
    }

    public var description: String {
        switch self {
        case .aes256GCM: return "AES-256-GCM"
        case .chaChaPoly: return "ChaCha20-Poly1305"
        }
    }
}
