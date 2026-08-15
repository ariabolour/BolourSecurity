import Foundation

/// A host a pinning policy applies to. Compared case-insensitively.
public struct PinnedHost: Sendable, Hashable, ExpressibleByStringLiteral, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value.lowercased() }
    public init(stringLiteral value: String) { self.init(value) }
    public var description: String { value }
}

/// A set of acceptable pins with a structurally mandatory backup: constructing one requires at least
/// a primary plus one more, so "pinning without a backup" — the classic self-inflicted outage — is a
/// compile error, not a runtime surprise.
public struct NonEmptyPins: Sendable, Hashable {
    public let pins: [SPKIHash]
    public init(_ first: SPKIHash, _ rest: SPKIHash...) {
        self.pins = [first] + rest
    }
}

/// What happens when a pin set passes its rotation deadline.
public enum PinExpiryBehavior: Sendable, Hashable {
    /// Pins are enforced until the given date; afterward evaluation fails **closed** with
    /// `CertificateError.pinSetExpired` — a loud, alertable signal to ship rotated pins, never a
    /// silent downgrade to unpinned TLS. `nil` means no expiry.
    case enforceUntil(Date?)
}

/// An SPKI-pinning policy for a host. Pins are enforced **in addition** to system trust, never
/// instead of it — a pinned-but-untrusted chain always fails.
public struct PinningPolicy: Sendable, Hashable {
    public let host: PinnedHost
    public let primary: SPKIHash
    public let backups: NonEmptyPins
    public let includeSubdomains: Bool
    public let expiry: PinExpiryBehavior

    public init(
        host: PinnedHost,
        primary: SPKIHash,
        backups: NonEmptyPins,
        includeSubdomains: Bool = false,
        expiry: PinExpiryBehavior = .enforceUntil(nil)
    ) {
        self.host = host
        self.primary = primary
        self.backups = backups
        self.includeSubdomains = includeSubdomains
        self.expiry = expiry
    }

    /// The full set of acceptable pins (primary + backups).
    var acceptablePins: Set<SPKIHash> { Set([primary] + backups.pins) }

    /// Whether this policy governs `candidate`.
    func governs(host candidate: String) -> Bool {
        let candidate = candidate.lowercased()
        if candidate == host.value { return true }
        if includeSubdomains { return candidate.hasSuffix("." + host.value) }
        return false
    }
}
