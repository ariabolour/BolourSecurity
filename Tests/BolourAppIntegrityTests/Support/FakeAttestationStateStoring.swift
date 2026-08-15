@testable import BolourAppIntegrity

/// An in-memory `AttestationStateStoring` double, so state-machine and persistence tests never
/// touch the real keychain (the same hostless-keychain constraint the other test targets document).
actor FakeAttestationStateStoring: AttestationStateStoring {
    private var stored: AttestationState?
    private(set) var saveCount = 0

    func load() async throws -> AttestationState? { stored }

    func save(_ state: AttestationState) async throws {
        stored = state
        saveCount += 1
    }
}
