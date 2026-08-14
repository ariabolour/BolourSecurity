import DeviceCheck
import Foundation
import BlurSecurityCore
import BlurKeychain
import BlurCrypto

/// App Attest as one lifecycle: key generation, one-time attestation, per-request assertions,
/// and invalidation recovery, behind the Core `AttestationProviding` seam.
///
/// One of the ecosystem's sanctioned actors: every state transition serializes through it, so
/// double-generation and attest/assert races are structurally gone. State is persisted via
/// `BlurKeychain` under the `keychain` passed to `init` so the lifecycle survives relaunches
/// without app-level bookkeeping.
///
/// - Note: **Honest limit.** The design intends the persisted state to always be device-only,
///   after-first-unlock protected, regardless of what `Keychain` configuration is passed in.
///   `Keychain`'s protection policy is fixed at construction and not independently overridable
///   per item, and its `service`/`accessGroup` fields aren't introspectable from another module —
///   so this actually uses whatever `Keychain` the caller supplies as-is (the default `Keychain()`
///   is already device-only via Core's own default). Callers who need `.afterFirstUnlock()`
///   specifically should construct their `Keychain` with that protection explicitly.
public actor AttestationService: AttestationProviding {
    private let stateStore: any AttestationStateStoring
    private let logger: (any SecurityEventLogger)?
    nonisolated let service: any AppAttestServicing
    private var cachedState: AttestationState?

    public init(keychain: Keychain = Keychain(), logger: (any SecurityEventLogger)? = nil) {
        self.init(
            stateStore: KeychainAttestationStateStore(keychain: keychain),
            logger: logger, service: RealAppAttestService()
        )
    }

    /// Test-only: substitutes scripted doubles for the real `DCAppAttestService` and keychain persistence.
    init(stateStore: any AttestationStateStoring, logger: (any SecurityEventLogger)?, service: any AppAttestServicing) {
        self.stateStore = stateStore
        self.logger = logger
        self.service = service
    }

    /// Whether this device/build can attest (simulators, unsupported OSes cannot). `DCAppAttestService`
    /// documents itself as safe to query from any queue, so this reads it without hopping onto the actor.
    public nonisolated var support: AttestationSupport {
        service.isSupported ? .supported : .unsupported(reason: AttestationService.unsupportedReason)
    }

    /// One-time (per key) attestation. Generates the SE key if needed, attests it against
    /// `challenge`, persists state, and returns the material the server verifies against Apple.
    ///
    /// A key can only ever be attested once (Apple's own constraint); calling this again after
    /// a successful attestation generates and attests a *fresh* key rather than erroring — the
    /// natural behavior for "re-enroll me."
    public func attestKey(challenge: ServerChallenge) async throws(IntegrityError) -> Attestation {
        guard case .supported = support else {
            throw IntegrityError.unsupported(AttestationService.unsupportedReason)
        }

        let currentState = try await loadState()
        let keyID: String
        switch currentState {
        case .keyGenerated(let existing):
            keyID = existing
        case .noKey, .attested, .invalidated:
            do { keyID = try await service.generateKey() }
            catch { throw mapping(error, keyID: nil) }
        }
        try await persist(.keyGenerated(keyID: keyID))

        let hashData = ClientData(precomputedHash: SHA256.digest(of: challenge.data)).hashData
        let attestationObject: Data
        do { attestationObject = try await service.attestKey(keyID, clientDataHash: hashData) }
        catch { throw mapping(error, keyID: keyID) }

        try await persist(.attested(keyID: keyID))
        logger?.log(.authenticationSucceeded)
        return Attestation(keyID: keyID, attestationObject: attestationObject)
    }

    /// Per-request proof. Throws ``IntegrityError/keyNotAttested`` before first attestation, and
    /// ``IntegrityError/keyInvalidated`` when the OS revoked the key — both with a documented,
    /// typed recovery path.
    public func assertion(for clientData: ClientData) async throws(IntegrityError) -> Assertion {
        let currentState = try await loadState()
        guard case .attested(let keyID) = currentState else {
            if case .invalidated = currentState { throw IntegrityError.keyInvalidated }
            throw IntegrityError.keyNotAttested
        }

        do {
            let assertionObject = try await service.generateAssertion(keyID, clientDataHash: clientData.hashData)
            return Assertion(keyID: keyID, assertionObject: assertionObject)
        } catch {
            let mapped = mapping(error, keyID: keyID)
            if case .keyInvalidated = mapped {
                try? await persist(.invalidated(keyID: keyID))
            }
            throw mapped
        }
    }

    /// Tears down local state after server-coordinated re-enrollment.
    public func resetAttestation() async throws(IntegrityError) {
        try await persist(.noKey)
    }

    // MARK: - State persistence

    private func loadState() async throws(IntegrityError) -> AttestationState {
        if let cachedState { return cachedState }
        do {
            let resolved = try await stateStore.load() ?? .noKey
            cachedState = resolved
            return resolved
        } catch {
            throw IntegrityError.underlying(UnknownAttestationFailure(description: "\(error)"))
        }
    }

    private func persist(_ newState: AttestationState) async throws(IntegrityError) {
        do {
            try await stateStore.save(newState)
            cachedState = newState
        } catch {
            throw IntegrityError.underlying(UnknownAttestationFailure(description: "\(error)"))
        }
    }

    // MARK: - Error mapping

    private func mapping(_ error: DCError, keyID: String?) -> IntegrityError {
        switch error.code {
        case .featureUnsupported:
            return .unsupported(AttestationService.unsupportedReason)
        case .invalidKey:
            return .keyInvalidated
        case .serverUnavailable:
            return .rateLimited(retryAfter: nil)
        case .invalidInput, .unknownSystemFailure:
            return .attestationRejected(underlying: error)
        @unknown default:
            return .attestationRejected(underlying: error)
        }
    }

    private nonisolated static var unsupportedReason: UnsupportedReason {
        #if targetEnvironment(simulator)
        return .simulator
        #else
        return .platform
        #endif
    }
}
