/// An internal seam around persisting ``AttestationState``, so tests can round-trip state
/// through a double rather than the real keychain (the same hostless-keychain constraint
/// `BolourKeychainTests`/`BolourSecureStorageTests` document).
protocol AttestationStateStoring: Sendable {
    func load() async throws -> AttestationState?
    func save(_ state: AttestationState) async throws
}
