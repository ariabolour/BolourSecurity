/// A freshly signed JWT.
public struct SignedJWT: Sendable {
    public let compactSerialization: String
    init(compactSerialization: String) { self.compactSerialization = compactSerialization }
}
