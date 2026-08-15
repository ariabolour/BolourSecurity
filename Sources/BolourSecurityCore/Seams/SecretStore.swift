/// A place secrets can be stored and retrieved by ``ItemKey``.
///
/// Defined in Core as a seam so higher modules can depend on "somewhere to keep a secret"
/// abstractly. `BolourKeychain` and `BolourSecureStorage` provide concrete conformances;
/// consumers such as `BolourOAuth` accept `any SecretStore`.
///
/// The seam is intentionally untyped in its `throws` clause — concrete conformers use their
/// own typed error domains internally, but the abstraction stays algorithm-agnostic.
public protocol SecretStore: Sendable {
    /// Stores `secret` under `key`, replacing any existing value.
    func store(_ secret: SecureBytes, for key: ItemKey) async throws
    /// Returns the secret stored under `key`, or `nil` if none exists.
    func secret(for key: ItemKey) async throws -> SecureBytes?
    /// Removes the secret stored under `key`, if any.
    func removeSecret(for key: ItemKey) async throws
}
