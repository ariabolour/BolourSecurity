import Testing
import Foundation
@testable import BlurCertificates
import BlurSecurityCore

@Suite("Trust evaluation")
struct TrustEvaluationTests {
    let host = "valid.blursecurity.test"

    /// An evaluator that trusts exactly our test root (no system roots).
    func evaluator(pinning: [PinningPolicy] = []) throws -> TrustEvaluator {
        TrustEvaluator(pinning: pinning, logger: nil, testAnchors: [try Fixture.certificate("root")])
    }

    private func wrongPin() throws -> SPKIHash {
        SPKIHash(of: try Fixture.certificate("root"))            // valid pin, wrong for the leaf
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
        await #expect(throws: CertificateError.self) {
            _ = try await evaluator().evaluate(CertificateChain([leaf]), for: "wrong.blursecurity.test")
        }
    }

    @Test("expired and not-yet-valid leaves fail closed", arguments: ["leaf-expired", "leaf-future"])
    func validityWindow(fixture: String) async throws {
        let leaf = try Fixture.certificate(fixture)
        await #expect(throws: CertificateError.self) {
            _ = try await evaluator().evaluate(CertificateChain([leaf]), for: host)
        }
    }

    @Test("a chain to an untrusted root fails closed")
    func untrustedRoot() async throws {
        let leaf = try Fixture.certificate("leaf-untrusted")
        await #expect(throws: CertificateError.self) {
            _ = try await evaluator().evaluate(CertificateChain([leaf]), for: host)
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

    @Test("no matching pin fails with pinMismatch")
    func pinMiss() async throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let zero = try SPKIHash(base64Encoded: Data(count: 32).base64EncodedString())
        let policy = PinningPolicy(host: PinnedHost(host), primary: try wrongPin(), backups: NonEmptyPins(zero))
        await #expect(throws: CertificateError.self) {
            _ = try await evaluator(pinning: [policy]).evaluate(CertificateChain([leaf]), for: host)
        }
    }

    @Test("an expired pin set fails closed")
    func pinExpired() async throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let policy = PinningPolicy(
            host: PinnedHost(host), primary: SPKIHash(of: leaf), backups: NonEmptyPins(SPKIHash(of: leaf)),
            expiry: .enforceUntil(Date(timeIntervalSince1970: 0))
        )
        await #expect(throws: CertificateError.self) {
            _ = try await evaluator(pinning: [policy]).evaluate(CertificateChain([leaf]), for: host)
        }
    }
}
