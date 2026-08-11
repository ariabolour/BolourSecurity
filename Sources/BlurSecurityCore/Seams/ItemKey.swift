/// A stable, reviewed identifier for a stored secret.
///
/// `ItemKey` is `ExpressibleByStringLiteral` for ergonomics, but apps are steered toward
/// declaring static members so key strings live in one reviewed place:
///
/// ```swift
/// extension ItemKey { static let refreshToken: ItemKey = "auth.refresh-token" }
/// ```
public struct ItemKey: Sendable, Hashable, ExpressibleByStringLiteral {
    /// The underlying key string.
    public let rawValue: String

    /// Creates a key from an explicit string.
    public init(_ rawValue: String) { self.rawValue = rawValue }

    /// Creates a key from a string literal.
    public init(stringLiteral value: String) { self.init(value) }
}
