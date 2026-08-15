/// A source of verification keys, keyed by rotation. `RemoteJWKSet` is the standard conformer;
/// apps needing a different transport (e.g. a bundled fixture in tests) can conform their own.
public protocol JWKSProviding: Sendable {
    func currentKeys() async throws -> [any JWTVerificationKey]
}
