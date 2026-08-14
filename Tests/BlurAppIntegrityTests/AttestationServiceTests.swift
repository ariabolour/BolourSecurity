import Testing
import DeviceCheck
import Foundation
@testable import BlurAppIntegrity

@Suite("AttestationService")
struct AttestationServiceTests {

    private func makeService(
        service: FakeAppAttestServicing = FakeAppAttestServicing(),
        store: FakeAttestationStateStoring = FakeAttestationStateStoring()
    ) -> AttestationService {
        AttestationService(stateStore: store, logger: nil, service: service)
    }

    @Test("first attestKey generates a key, attests it, and returns the attestation")
    func firstAttestation() async throws {
        let fake = FakeAppAttestServicing()
        let attestation = try await makeService(service: fake).attestKey(challenge: ServerChallenge(Data("challenge".utf8)))
        #expect(attestation.keyID == "fake-key-id")
        #expect(attestation.attestationObject == Data("attestation".utf8))
        #expect(fake.generateKeyCallCount == 1)
        #expect(fake.attestedKeyIDs == ["fake-key-id"])
    }

    @Test("assertion(for:) before any attestation throws keyNotAttested")
    func assertionBeforeAttestationThrows() async {
        let service = makeService()
        do {
            _ = try await service.assertion(for: ClientData(hashing: Data(), serverNonce: Data()))
            Issue.record("expected keyNotAttested")
        } catch IntegrityError.keyNotAttested {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("assertion(for:) after attestation succeeds against the attested key")
    func assertionAfterAttestationSucceeds() async throws {
        let fake = FakeAppAttestServicing()
        let service = makeService(service: fake)
        _ = try await service.attestKey(challenge: ServerChallenge(Data("challenge".utf8)))

        let assertion = try await service.assertion(for: ClientData(hashing: Data("body".utf8), serverNonce: Data("nonce".utf8)))
        #expect(assertion.keyID == "fake-key-id")
        #expect(fake.assertedKeyIDs == ["fake-key-id"])
    }

    @Test("re-attesting after a successful attestation generates a fresh key")
    func reattestationGeneratesFreshKey() async throws {
        let fake = FakeAppAttestServicing()
        let service = makeService(service: fake)
        _ = try await service.attestKey(challenge: ServerChallenge(Data("c1".utf8)))
        fake.generateKeyResult = .success("second-key-id")
        let second = try await service.attestKey(challenge: ServerChallenge(Data("c2".utf8)))

        #expect(second.keyID == "second-key-id")
        #expect(fake.generateKeyCallCount == 2)
    }

    @Test("attestKey when unsupported throws without ever calling generateKey")
    func unsupportedShortCircuits() async {
        let fake = FakeAppAttestServicing()
        fake.isSupported = false
        let service = makeService(service: fake)
        await #expect(throws: (any Error).self) {
            _ = try await service.attestKey(challenge: ServerChallenge(Data()))
        }
        #expect(fake.generateKeyCallCount == 0)
    }

    @Test("an invalidated key surfaces on assertion, persists, and recovers via resetAttestation")
    func invalidationRecovery() async throws {
        let fake = FakeAppAttestServicing()
        let store = FakeAttestationStateStoring()
        let service = makeService(service: fake, store: store)
        _ = try await service.attestKey(challenge: ServerChallenge(Data()))

        fake.generateAssertionResult = .failure(DCError(.invalidKey))
        try await expectKeyInvalidated { _ = try await service.assertion(for: ClientData(hashing: Data(), serverNonce: Data())) }
        // The invalidation is persisted: a second call sees it directly, without re-asking the
        // (already-invalid) key.
        let assertedCountAfterFirstFailure = fake.assertedKeyIDs.count
        try await expectKeyInvalidated { _ = try await service.assertion(for: ClientData(hashing: Data(), serverNonce: Data())) }
        #expect(fake.assertedKeyIDs.count == assertedCountAfterFirstFailure)

        try await service.resetAttestation()
        fake.generateKeyResult = .success("recovered-key-id")
        fake.generateAssertionResult = .success(Data("ok".utf8))
        let attestation = try await service.attestKey(challenge: ServerChallenge(Data()))
        #expect(attestation.keyID == "recovered-key-id")
        let assertion = try await service.assertion(for: ClientData(hashing: Data(), serverNonce: Data()))
        #expect(assertion.keyID == "recovered-key-id")
    }

    @Test("resetAttestation clears state so the next attestKey behaves like a first attestation")
    func resetClearsState() async throws {
        let fake = FakeAppAttestServicing()
        let service = makeService(service: fake)
        _ = try await service.attestKey(challenge: ServerChallenge(Data()))
        try await service.resetAttestation()
        do {
            _ = try await service.assertion(for: ClientData(hashing: Data(), serverNonce: Data()))
            Issue.record("expected keyNotAttested")
        } catch IntegrityError.keyNotAttested {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("state persisted by one actor instance resumes correctly in a fresh instance over the same store (simulated relaunch)")
    func statePersistsAcrossFreshInstances() async throws {
        let store = FakeAttestationStateStoring()
        let first = makeService(service: FakeAppAttestServicing(), store: store)
        _ = try await first.attestKey(challenge: ServerChallenge(Data()))

        // A brand-new actor, same backing store — mirrors an app relaunch.
        let secondFake = FakeAppAttestServicing()
        let second = makeService(service: secondFake, store: store)
        let assertion = try await second.assertion(for: ClientData(hashing: Data(), serverNonce: Data()))
        #expect(assertion.keyID == "fake-key-id")
        // The second instance never had to generate or attest a key itself.
        #expect(secondFake.generateKeyCallCount == 0)
    }

    // MARK: - DCError -> IntegrityError mapping

    @Test(
        "every DCError code maps to the documented IntegrityError",
        arguments: [
            (DCError.Code.featureUnsupported, "unsupported"),
            (.invalidKey, "keyInvalidated"),
            (.serverUnavailable, "rateLimited"),
            (.invalidInput, "attestationRejected"),
            (.unknownSystemFailure, "attestationRejected"),
        ]
    )
    func dcErrorMapping(code: DCError.Code, expectedCaseLabel: String) async {
        let fake = FakeAppAttestServicing()
        fake.attestKeyResult = .failure(DCError(code))
        let service = makeService(service: fake)

        do {
            _ = try await service.attestKey(challenge: ServerChallenge(Data()))
            Issue.record("expected attestKey to throw")
        } catch {
            #expect(caseLabel(of: error) == expectedCaseLabel)
        }
    }

    private func expectKeyInvalidated(_ operation: () async throws -> Void) async throws {
        do {
            try await operation()
            Issue.record("expected keyInvalidated")
        } catch IntegrityError.keyInvalidated {
            // expected
        }
    }

    private func caseLabel(of error: IntegrityError) -> String {
        switch error {
        case .unsupported: return "unsupported"
        case .keyNotAttested: return "keyNotAttested"
        case .keyInvalidated: return "keyInvalidated"
        case .attestationRejected: return "attestationRejected"
        case .serverChallengeRequired: return "serverChallengeRequired"
        case .rateLimited: return "rateLimited"
        case .underlying: return "underlying"
        }
    }
}
