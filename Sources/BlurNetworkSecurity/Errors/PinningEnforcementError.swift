import BlurCertificates
import BlurSecurityCore

/// The closed failure domain of session-level trust and pinning enforcement.
///
/// - Note: `tlsVersionBelowMinimum` names a failure mode that ``URLSession/secure(policy:configuration:delegate:delegateQueue:)``
///   prevents *structurally*, not by catching it here: the minimum floor is applied to the
///   session's `URLSessionConfiguration` before any connection is attempted, so a server that
///   cannot meet it fails the TLS handshake itself and the case never reaches our delegate.
///   The case stays part of this closed domain because it is a real, named reason a connection
///   can be refused — documentation and any future direct-evaluation entry point need the
///   vocabulary — even though today's `URLSession` integration cannot observe the negotiated
///   protocol version at challenge time to throw it itself. An honest limit, not an oversight.
public enum PinningEnforcementError: SecurityError {
    case evaluationFailed(host: String, underlying: CertificateError)
    case unpinnedHostRefused(host: String)
    case tlsVersionBelowMinimum(host: String)
    /// Construction of an ``UnvalidatedTrustOverride`` was attempted for a host that is not
    /// loopback, RFC 1918 private, or `.local` — refused at the developer's desk.
    case overrideHostNotLocal(String)

    public var failureIsRecoverable: Bool {
        switch self {
        case .evaluationFailed, .unpinnedHostRefused, .tlsVersionBelowMinimum:
            // The failure tracks the server/network, not the caller; a retry or a fixed
            // deployment can plausibly succeed.
            return true
        case .overrideHostNotLocal:
            // A programmer error: the argument itself must change.
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .evaluationFailed(let host, let underlying):
            return "Trust evaluation failed for “\(host)”: \(underlying.errorDescription ?? "unknown error")."
        case .unpinnedHostRefused(let host):
            return "“\(host)” has no pinning policy and the session refuses unpinned hosts."
        case .tlsVersionBelowMinimum(let host):
            return "The connection to “\(host)” could not meet the session's minimum TLS version."
        case .overrideHostNotLocal(let host):
            return "“\(host)” is not a local-development host (loopback, RFC 1918, or .local)."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .evaluationFailed:
            return "Confirm the server's certificate chain and that the app ships current SPKI pins."
        case .unpinnedHostRefused:
            return "Add a PinningPolicy for the host, or set unpinnedHostBehavior to .systemTrust."
        case .tlsVersionBelowMinimum:
            return "Upgrade the server's TLS configuration, or lower NetworkSecurityPolicy.minimumTLS."
        case .overrideHostNotLocal:
            return "UnvalidatedTrustOverride only accepts loopback/RFC 1918/.local hosts; never a real host."
        }
    }

    public var debugDescription: String {
        "PinningEnforcementError(\(errorDescription ?? "unknown"))"
    }
}
