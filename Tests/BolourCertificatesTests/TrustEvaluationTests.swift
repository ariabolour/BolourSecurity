import Testing
import Foundation
@testable import BolourCertificates
import BolourSecurityCore

/// - Note: Every test below except the three happy paths asserts that a bad chain is *rejected*.
///   That shape is only meaningful where `SecTrust` actually works — on a host where trust
///   evaluation is broken outright, a "fails closed" assertion passes for the wrong reason. Hence
///   both the suite-level probe and the per-test insistence on *which* failure occurred; see
///   ``SystemTrustProbe``.
@Suite("Trust evaluation", .tags(.requiresSecurityServices), .enabled(if: SystemTrustProbe.isAvailable))
struct TrustEvaluationTests {
    let host = "valid.boloursecurity.test"

    /// An evaluator that trusts exactly our test root (no system roots).
    func evaluator(pinning: [PinningPolicy] = []) throws -> TrustEvaluator {
        TrustEvaluator(pinning: pinning, logger: nil, testAnchors: [try Fixture.certificate("root")])
    }

    private func wrongPin() throws -> SPKIHash {
        SPKIHash(of: try Fixture.certificate("root"))            // valid pin, wrong for the leaf
    }

    /// Runs `operation`, requires that it threw a `CertificateError`, and returns it — recording
    /// a failure (rather than skipping, or passing quietly) if it succeeded instead.
    private func failure(
        _ operation: () async throws -> EvaluatedCertificateChain,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async throws -> CertificateError {
        do {
            _ = try await operation()
        } catch let error as CertificateError {
            // The environment is probed once at suite level, but a mid-run change (a keychain
            // locking, a daemon becoming unreachable) would otherwise become a silent false pass.
            #expect(
                !SystemTrustProbe.isInfrastructureFailure(error),
                "the Security subsystem could not evaluate the chain, so this test proved nothing: \(error)",
                sourceLocation: sourceLocation
            )
            return error
        }
        Issue.record("expected the evaluation to fail closed, but it succeeded", sourceLocation: sourceLocation)
        throw CertificateError.systemTrustFailed(underlying: errSecSuccess, host: host)
    }

    @Test("a valid chain to a trusted root passes")
    func valid() async throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let result = try await evaluator().evaluate(CertificateChain([leaf]), for: host)
        #expect(result.host == host)
        #expect(result.matchedPin == nil)
    }

    @Test("wrong host fails closed")
    func wrongHost() async throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let error = try await failure {
            try await evaluator().evaluate(CertificateChain([leaf]), for: "wrong.boloursecurity.test")
        }
        guard case .systemTrustFailed(_, let rejectedHost) = error else {
            Issue.record("expected systemTrustFailed, got \(error)")
            return
        }
        #expect(rejectedHost == "wrong.boloursecurity.test")
    }

    @Test("expired and not-yet-valid leaves fail closed", arguments: ["leaf-expired", "leaf-future"])
    func validityWindow(fixture: String) async throws {
        let leaf = try Fixture.certificate(fixture)
        let error = try await failure {
            try await evaluator().evaluate(CertificateChain([leaf]), for: host)
        }
        guard case .systemTrustFailed = error else {
            Issue.record("expected systemTrustFailed, got \(error)")
            return
        }
    }

    @Test("a chain to an untrusted root fails closed")
    func untrustedRoot() async throws {
        let leaf = try Fixture.certificate("leaf-untrusted")
        let error = try await failure {
            try await evaluator().evaluate(CertificateChain([leaf]), for: host)
        }
        guard case .systemTrustFailed = error else {
            Issue.record("expected systemTrustFailed, got \(error)")
            return
        }
    }

    @Test("a matching primary pin is accepted")
    func pinPrimaryHit() async throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let policy = PinningPolicy(host: PinnedHost(host), primary: SPKIHash(of: leaf), backups: NonEmptyPins(try wrongPin()))
        let result = try await evaluator(pinning: [policy]).evaluate(CertificateChain([leaf]), for: host)
        #expect(result.matchedPin == SPKIHash(of: leaf))
    }

    @Test("a matching backup pin is accepted")
    func pinBackupHit() async throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let policy = PinningPolicy(host: PinnedHost(host), primary: try wrongPin(), backups: NonEmptyPins(SPKIHash(of: leaf)))
        let result = try await evaluator(pinning: [policy]).evaluate(CertificateChain([leaf]), for: host)
        #expect(result.matchedPin == SPKIHash(of: leaf))
    }

    /// Pins are checked *after* system trust, so this rejection must be `pinMismatch`
    /// specifically. Accepting any `CertificateError` here would let a broken trust subsystem —
    /// which rejects every chain before pinning is ever consulted — pass the test.
    @Test("no matching pin fails with pinMismatch")
    func pinMiss() async throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let zero = try SPKIHash(base64Encoded: Data(count: 32).base64EncodedString())
        let policy = PinningPolicy(host: PinnedHost(host), primary: try wrongPin(), backups: NonEmptyPins(zero))
        let error = try await failure {
            try await evaluator(pinning: [policy]).evaluate(CertificateChain([leaf]), for: host)
        }
        guard case .pinMismatch(let mismatchedHost) = error else {
            Issue.record("expected pinMismatch, got \(error)")
            return
        }
        #expect(mismatchedHost == host)
    }

    @Test("an expired pin set fails closed")
    func pinExpired() async throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let deadline = Date(timeIntervalSince1970: 0)
        let policy = PinningPolicy(
            host: PinnedHost(host), primary: SPKIHash(of: leaf), backups: NonEmptyPins(SPKIHash(of: leaf)),
            expiry: .enforceUntil(deadline)
        )
        let error = try await failure {
            try await evaluator(pinning: [policy]).evaluate(CertificateChain([leaf]), for: host)
        }
        guard case .pinSetExpired(let expiredHost, let expiredAt) = error else {
            Issue.record("expected pinSetExpired, got \(error)")
            return
        }
        #expect(expiredHost == host)
        #expect(expiredAt == deadline)
    }
}
