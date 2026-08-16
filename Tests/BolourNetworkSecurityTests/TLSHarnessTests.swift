import Testing
import Foundation
import Network
@testable import BolourNetworkSecurity
@testable import BolourCertificates

/// The integration-level proof: real TLS handshakes, through a real `URLSession`, against a
/// real (if minimal) in-process server — over the matrix the module exists to get right.
/// `TrustEvaluator` here always carries the harness's own root as a test anchor (mirroring
/// `TrustEvaluatorTests` in BolourCertificatesTests) so these tests exercise pinning/refusal
/// behavior without depending on any real public CA.
///
/// Gated on ``NetworkFixtures/isAvailable``: standing the harness up needs a `SecIdentity`, and
/// on macOS the only route to one runs through the default keychain — unavailable on a headless
/// or sandboxed host. See `docs/IntegrationTesting.md`.
@Suite(
    "In-process TLS harness",
    .tags(.requiresSecurityServices),
    .enabled(if: NetworkFixtures.isAvailable)
)
struct TLSHarnessTests {

    private func startServer(
        minimumVersion: tls_protocol_version_t = .TLSv12,
        maximumVersion: tls_protocol_version_t = .TLSv13
    ) async throws -> LocalTLSServer {
        let server = LocalTLSServer()
        try await server.start(
            identity: try NetworkFixtures.serverIdentity(),
            minimumVersion: minimumVersion, maximumVersion: maximumVersion
        )
        return server
    }

    private func session(
        pinning: [PinningPolicy] = [],
        unpinnedHostBehavior: UnpinnedHostBehavior = .systemTrust,
        minimumTLS: TLSVersion = .v1_2
    ) throws -> URLSession {
        let evaluator = TrustEvaluator(pinning: pinning, logger: nil, testAnchors: [try NetworkFixtures.root()])
        let policy = NetworkSecurityPolicy(
            pinning: pinning, minimumTLS: minimumTLS, unpinnedHostBehavior: unpinnedHostBehavior
        )
        let delegate = SecureSessionDelegate(policy: policy, forwardingTo: nil, evaluator: evaluator)
        let configuration = URLSessionConfiguration.ephemeral
        // Mirrors what URLSession.secure(policy:) itself wires up.
        configuration.tlsMinimumSupportedProtocolVersion = minimumTLS.protocolVersion
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    @Test("a pinned host with the matching SPKI pin succeeds")
    func pinnedMatch() async throws {
        let server = try await startServer()
        defer { server.stop() }
        let policy = [
            PinningPolicy(
                host: "localhost", primary: try NetworkFixtures.leafPin(),
                backups: NonEmptyPins(try NetworkFixtures.decoyPin())
            )
        ]
        let (_, response) = try await session(pinning: policy)
            .data(from: URL(string: "https://localhost:\(server.port)/")!)
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
    }

    @Test("a pinned host presenting a chain that matches none of the pins fails closed")
    func pinnedMismatch() async throws {
        let server = try await startServer()
        defer { server.stop() }
        let decoyPin = try NetworkFixtures.decoyPin()
        let policy = [PinningPolicy(host: "localhost", primary: decoyPin, backups: NonEmptyPins(decoyPin))]
        await #expect(throws: URLError.self) {
            _ = try await session(pinning: policy).data(from: URL(string: "https://localhost:\(server.port)/")!)
        }
    }

    @Test("an unpinned host under .systemTrust succeeds")
    func unpinnedSystemTrust() async throws {
        let server = try await startServer()
        defer { server.stop() }
        let (_, response) = try await session(unpinnedHostBehavior: .systemTrust)
            .data(from: URL(string: "https://localhost:\(server.port)/")!)
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
    }

    @Test("an unpinned host under .refuse fails closed")
    func unpinnedRefuse() async throws {
        let server = try await startServer()
        defer { server.stop() }
        await #expect(throws: URLError.self) {
            _ = try await session(unpinnedHostBehavior: .refuse)
                .data(from: URL(string: "https://localhost:\(server.port)/")!)
        }
    }

    @Test("an expired pin set fails closed even with the correct pin")
    func expiredPinSet() async throws {
        let server = try await startServer()
        defer { server.stop() }
        let expired = PinningPolicy(
            host: "localhost", primary: try NetworkFixtures.leafPin(),
            backups: NonEmptyPins(try NetworkFixtures.decoyPin()),
            expiry: .enforceUntil(Date(timeIntervalSince1970: 0))
        )
        await #expect(throws: URLError.self) {
            _ = try await session(pinning: [expired]).data(from: URL(string: "https://localhost:\(server.port)/")!)
        }
    }

    @Test("a server that cannot meet the session's minimum TLS version fails the handshake")
    func tlsFloorRejectsWeakServer() async throws {
        let server = try await startServer(minimumVersion: .TLSv12, maximumVersion: .TLSv12)
        defer { server.stop() }
        await #expect(throws: URLError.self) {
            _ = try await session(minimumTLS: .v1_3).data(from: URL(string: "https://localhost:\(server.port)/")!)
        }
    }

    @Test("a server meeting the session's minimum TLS version succeeds")
    func tlsFloorAcceptsMatchingServer() async throws {
        let server = try await startServer(minimumVersion: .TLSv13, maximumVersion: .TLSv13)
        defer { server.stop() }
        let (_, response) = try await session(minimumTLS: .v1_3)
            .data(from: URL(string: "https://localhost:\(server.port)/")!)
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
    }

    @Test("an UnvalidatedTrustOverride host bypasses evaluation entirely, even for a chain that would fail pinning")
    func unvalidatedOverrideBypassesEvaluation() async throws {
        let server = try await startServer()
        defer { server.stop() }
        let decoyPin = try NetworkFixtures.decoyPin()
        let policy = NetworkSecurityPolicy(
            pinning: [PinningPolicy(host: "localhost", primary: decoyPin, backups: NonEmptyPins(decoyPin))]
        ).allowing(try UnvalidatedTrustOverride(forLocalDevelopmentHosts: ["localhost"]))
        // No test anchors here on purpose: an evaluator that actually ran would fail system
        // trust too (untrusted root), not just the pin. The override must still succeed.
        let delegate = SecureSessionDelegate(
            policy: policy, forwardingTo: nil, evaluator: TrustEvaluator(pinning: policy.pinning, logger: nil)
        )
        let configuration = URLSessionConfiguration.ephemeral
        let overriddenSession = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        let (_, response) = try await overriddenSession.data(from: URL(string: "https://localhost:\(server.port)/")!)
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
    }
}
