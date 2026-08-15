import Testing
import Foundation
import Security
@testable import BolourNetworkSecurity
@testable import BolourCertificates

/// The property this suite exists to prove: whatever the injected trust evaluator does — throw,
/// take a while and then throw, or hand back a chain that should be refused — `decide(serverTrust:host:)`
/// only ever returns a credential or throws. There is no third outcome, and in particular no
/// path that resembles "give up and allow the connection anyway."
@Suite("Fail-closed under fault injection")
struct FailClosedTests {

    private enum TestSetupError: Error { case trustCreationFailed(status: OSStatus) }

    private func makeSecTrust(derCertificates: [Data]) throws -> SecTrust {
        let secCertificates = derCertificates.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        let policy = SecPolicyCreateSSL(true, "localhost" as CFString)
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(secCertificates as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust else {
            throw TestSetupError.trustCreationFailed(status: status)
        }
        return trust
    }

    private struct ThrowingEvaluator: ChainEvaluating {
        func evaluate(_ chain: CertificateChain, for host: String) async throws(CertificateError) -> EvaluatedCertificateChain {
            throw CertificateError.systemTrustFailed(underlying: -1, host: host)
        }
    }

    private struct SlowThenThrowingEvaluator: ChainEvaluating {
        func evaluate(_ chain: CertificateChain, for host: String) async throws(CertificateError) -> EvaluatedCertificateChain {
            try? await Task.sleep(for: .milliseconds(150))
            throw CertificateError.revocationCheckFailed(host: host)
        }
    }

    private struct SucceedingUnpinnedEvaluator: ChainEvaluating {
        func evaluate(_ chain: CertificateChain, for host: String) async throws(CertificateError) -> EvaluatedCertificateChain {
            EvaluatedCertificateChain(leaf: chain.certificates[0], host: host, evaluatedAt: Date(), matchedPin: nil)
        }
    }

    @Test("a throwing evaluator fails closed")
    func throwingEvaluatorFailsClosed() async throws {
        let leaf = try NetworkFixtures.leaf()
        let trust = try makeSecTrust(derCertificates: [leaf.derRepresentation])
        let delegate = SecureSessionDelegate(
            policy: NetworkSecurityPolicy(), forwardingTo: nil, evaluator: ThrowingEvaluator()
        )
        await #expect(throws: PinningEnforcementError.self) {
            _ = try await delegate.decide(serverTrust: trust, host: "localhost")
        }
    }

    @Test("a slow-then-throwing evaluator still fails closed, never early-succeeds")
    func slowEvaluatorFailsClosed() async throws {
        let leaf = try NetworkFixtures.leaf()
        let trust = try makeSecTrust(derCertificates: [leaf.derRepresentation])
        let delegate = SecureSessionDelegate(
            policy: NetworkSecurityPolicy(), forwardingTo: nil, evaluator: SlowThenThrowingEvaluator()
        )
        let clock = ContinuousClock()
        let start = clock.now
        await #expect(throws: PinningEnforcementError.self) {
            _ = try await delegate.decide(serverTrust: trust, host: "localhost")
        }
        #expect(start.duration(to: clock.now) >= .milliseconds(140))
    }

    @Test("an unpinned host under .refuse fails closed even when the evaluator reports success")
    func unpinnedRefuseFailsClosed() async throws {
        let leaf = try NetworkFixtures.leaf()
        let trust = try makeSecTrust(derCertificates: [leaf.derRepresentation])
        let policy = NetworkSecurityPolicy(unpinnedHostBehavior: .refuse)
        let delegate = SecureSessionDelegate(
            policy: policy, forwardingTo: nil, evaluator: SucceedingUnpinnedEvaluator()
        )
        do {
            _ = try await delegate.decide(serverTrust: trust, host: "localhost")
            Issue.record("expected unpinnedHostRefused to be thrown")
        } catch PinningEnforcementError.unpinnedHostRefused(let host) {
            #expect(host == "localhost")
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("an unpinned host under .systemTrust succeeds")
    func unpinnedSystemTrustSucceeds() async throws {
        let leaf = try NetworkFixtures.leaf()
        let trust = try makeSecTrust(derCertificates: [leaf.derRepresentation])
        let policy = NetworkSecurityPolicy(unpinnedHostBehavior: .systemTrust)
        let delegate = SecureSessionDelegate(
            policy: policy, forwardingTo: nil, evaluator: SucceedingUnpinnedEvaluator()
        )
        _ = try await delegate.decide(serverTrust: trust, host: "localhost")
    }
}
