import Network

/// A minimum TLS protocol floor for a ``NetworkSecurityPolicy``.
public enum TLSVersion: Sendable, Comparable {
    case v1_2
    case v1_3

    /// The `Network` framework representation, used to configure the session's transport floor.
    var protocolVersion: tls_protocol_version_t {
        switch self {
        case .v1_2: return .TLSv12
        case .v1_3: return .TLSv13
        }
    }

    private var ordinal: Int {
        switch self {
        case .v1_2: return 0
        case .v1_3: return 1
        }
    }

    public static func < (lhs: TLSVersion, rhs: TLSVersion) -> Bool {
        lhs.ordinal < rhs.ordinal
    }
}
