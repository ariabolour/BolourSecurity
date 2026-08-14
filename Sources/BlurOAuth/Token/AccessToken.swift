import Foundation

/// A usable access token. The raw string is deliberately not a public `String` property —
/// `headerValue` and construction-only access cover real uses without inviting string
/// interpolation of a bearer token into logs.
public struct AccessToken: Sendable {
    let value: String
    public let expiresAt: Date?

    init(value: String, expiresAt: Date?) {
        self.value = value
        self.expiresAt = expiresAt
    }

    /// `"Bearer <token>"` — ready for `URLRequest`'s `Authorization` header.
    public var headerValue: String { "Bearer \(value)" }
}
