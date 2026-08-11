/// A keychain access group — the sharing boundary for items across an app, its extensions,
/// and an app group.
///
/// Use the labelled factories at the call site so intent is explicit:
///
/// ```swift
/// Keychain(accessGroup: .appGroup("group.com.example.shared"))
/// ```
public struct AccessGroup: Sendable, Hashable, ExpressibleByStringLiteral {
    /// The raw access-group string, as it appears in the Keychain Sharing entitlement.
    public let rawValue: String

    /// Creates an access group from an explicit string.
    public init(_ rawValue: String) { self.rawValue = rawValue }

    /// Creates an access group from a string literal.
    public init(stringLiteral value: String) { self.init(value) }

    /// An app-group access group (e.g. `"group.com.example.shared"`), shared with extensions
    /// and widgets in the same app group.
    public static func appGroup(_ identifier: String) -> AccessGroup { AccessGroup(identifier) }

    /// A team-prefixed access group as declared in the app's Keychain Sharing entitlement.
    public static func team(_ identifier: String) -> AccessGroup { AccessGroup(identifier) }
}
