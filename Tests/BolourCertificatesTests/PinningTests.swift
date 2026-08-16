import Testing
import Foundation
@testable import BolourCertificates

@Suite("Pinning")
struct PinningTests {

    @Test("SPKIHash matches the openssl reference pin")
    func spkiKnownAnswer() throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let root = try Fixture.certificate("root")
        #expect(SPKIHash(of: leaf).base64EncodedString == "47Mg1fFM+MauiMoHRCsePwdlVpaO4FYDUrDsmJ6NZHA=")
        #expect(SPKIHash(of: root).base64EncodedString == "FuoJZxNhAyxoo5nDaskgkOj6962JNoi/KV2UO/auc6c=")
    }

    @Test("SPKIHash base64 round-trips and rejects bad encodings")
    func spkiEncoding() throws {
        let pin = "47Mg1fFM+MauiMoHRCsePwdlVpaO4FYDUrDsmJ6NZHA="
        #expect(try SPKIHash(base64Encoded: pin).base64EncodedString == pin)
        #expect(throws: CertificateError.self) { _ = try SPKIHash(base64Encoded: "not-base64!!") }
        #expect(throws: CertificateError.self) { _ = try SPKIHash(base64Encoded: "AAAA") }   // wrong length
    }

    @Test("SPKIHash is Codable")
    func codable() throws {
        let hash = try SPKIHash(base64Encoded: "47Mg1fFM+MauiMoHRCsePwdlVpaO4FYDUrDsmJ6NZHA=")
        let encoded = try JSONEncoder().encode(hash)
        #expect(try JSONDecoder().decode(SPKIHash.self, from: encoded) == hash)
    }

    @Test("a policy always carries a primary plus at least one backup")
    func mandatoryBackup() throws {
        let a = try SPKIHash(base64Encoded: "47Mg1fFM+MauiMoHRCsePwdlVpaO4FYDUrDsmJ6NZHA=")
        let b = try SPKIHash(base64Encoded: "FuoJZxNhAyxoo5nDaskgkOj6962JNoi/KV2UO/auc6c=")
        let policy = PinningPolicy(host: "api.example.com", primary: a, backups: NonEmptyPins(b))
        #expect(policy.acceptablePins == Set([a, b]))
        // A single-pin policy is unconstructible: NonEmptyPins requires at least one backup.
    }

    @Test("host matching is case-insensitive and honors includeSubdomains")
    func hostMatching() throws {
        let a = try SPKIHash(base64Encoded: "47Mg1fFM+MauiMoHRCsePwdlVpaO4FYDUrDsmJ6NZHA=")
        let b = try SPKIHash(base64Encoded: "FuoJZxNhAyxoo5nDaskgkOj6962JNoi/KV2UO/auc6c=")
        let exact = PinningPolicy(host: "API.Example.com", primary: a, backups: NonEmptyPins(b))
        #expect(exact.governs(host: "api.example.com"))
        #expect(exact.governs(host: "sub.api.example.com") == false)

        let wildcard = PinningPolicy(host: "example.com", primary: a, backups: NonEmptyPins(b), includeSubdomains: true)
        #expect(wildcard.governs(host: "api.example.com"))
        #expect(wildcard.governs(host: "example.com"))
    }
}
