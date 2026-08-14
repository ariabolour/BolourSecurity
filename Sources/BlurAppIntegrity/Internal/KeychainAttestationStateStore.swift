import BlurSecurityCore
import BlurKeychain

/// The real `AttestationStateStoring` conformer: persists through a `Keychain`.
struct KeychainAttestationStateStore: AttestationStateStoring {
    private let keychain: Keychain
    private let itemKey: ItemKey

    init(keychain: Keychain, itemKey: ItemKey = "blur.appintegrity.attestation-state") {
        self.keychain = keychain
        self.itemKey = itemKey
    }

    func load() async throws -> AttestationState? {
        try await keychain.value(AttestationState.self, for: itemKey)
    }

    func save(_ state: AttestationState) async throws {
        try await keychain.store(state, for: itemKey)
    }
}
