/// A named vault. Two `Vault.open` calls with the same name address the same on-disk container
/// and the same keychain-held master key.
public struct VaultName: Sendable, Hashable, ExpressibleByStringLiteral, CustomStringConvertible {
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
    public init(stringLiteral value: String) { self.init(value) }
    public var description: String { rawValue }
}
