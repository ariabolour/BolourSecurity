/// The OAuth scopes an authorization request asks for.
public struct ScopeSet: Sendable, Hashable, ExpressibleByArrayLiteral {
    let values: Set<String>

    public init(arrayLiteral elements: String...) {
        self.values = Set(elements)
    }

    public init(_ values: some Sequence<String>) {
        self.values = Set(values)
    }

    /// `openid profile email` — the building blocks most OIDC sign-ins start from.
    public static let openID: ScopeSet = ["openid", "profile", "email"]

    /// Unions two scope sets — `.openID + ["offline_access"]`.
    public static func + (lhs: ScopeSet, rhs: ScopeSet) -> ScopeSet {
        ScopeSet(lhs.values.union(rhs.values))
    }

    var spaceSeparated: String { values.sorted().joined(separator: " ") }
}
