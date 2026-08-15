/// A structured, pre-redacted security event.
///
/// The set of events is **closed** and carries no free-form `String` payload: if you cannot
/// put a secret in, you cannot leak one through the logger. New event kinds are added
/// deliberately as modules land.
public struct SecurityEvent: Sendable, Hashable {
    /// The closed set of loggable events.
    public enum Kind: Sendable, Hashable {
        /// A secret was stored.
        case itemStored
        /// A secret was read.
        case itemRead
        /// A secret was removed.
        case itemRemoved
        /// A local authentication succeeded.
        case authenticationSucceeded
        /// A local authentication failed.
        case authenticationFailed
        /// Certificate pinning rejected a connection to `host` (a hostname is not a secret).
        case pinningFailure(host: String)
        /// A local-development trust override was constructed, unconditionally bypassing
        /// certificate validation for `hosts`. Always logged, regardless of the app's own
        /// injected logger — this event is meant to be impossible to silence.
        case developmentTrustOverrideCreated(hosts: Set<String>)
    }

    /// The event that occurred.
    public let kind: Kind

    /// Wraps a ``Kind`` as an event.
    public init(_ kind: Kind) { self.kind = kind }
}

extension SecurityEvent {
    /// A secret was stored.
    public static let itemStored = SecurityEvent(.itemStored)
    /// A secret was read.
    public static let itemRead = SecurityEvent(.itemRead)
    /// A secret was removed.
    public static let itemRemoved = SecurityEvent(.itemRemoved)
    /// A local authentication succeeded.
    public static let authenticationSucceeded = SecurityEvent(.authenticationSucceeded)
    /// A local authentication failed.
    public static let authenticationFailed = SecurityEvent(.authenticationFailed)
    /// Certificate pinning rejected a connection to `host`.
    public static func pinningFailure(host: String) -> SecurityEvent {
        SecurityEvent(.pinningFailure(host: host))
    }
    /// A local-development trust override was constructed for `hosts`.
    public static func developmentTrustOverrideCreated(hosts: Set<String>) -> SecurityEvent {
        SecurityEvent(.developmentTrustOverrideCreated(hosts: hosts))
    }
}
