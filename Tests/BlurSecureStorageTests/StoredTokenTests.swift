import Testing
import Foundation
@testable import BlurSecureStorage
import BlurSecurityCore

@Suite("StoredToken")
struct StoredTokenTests {

    @Test("round-trips through SecureBytes, with and without expiry")
    func roundTrip() throws {
        let withExpiry = StoredToken(value: SecureBytes(Array("secret".utf8)), expiresAt: Date(timeIntervalSince1970: 2_000_000_000))
        let restored = try StoredToken(secureBytes: try withExpiry.secureBytesRepresentation())
        #expect(restored.value == withExpiry.value)
        #expect(restored.expiresAt == withExpiry.expiresAt)

        let withoutExpiry = StoredToken(value: SecureBytes(Array("secret2".utf8)), expiresAt: nil)
        let restored2 = try StoredToken(secureBytes: try withoutExpiry.secureBytesRepresentation())
        #expect(restored2.value == withoutExpiry.value)
        #expect(restored2.expiresAt == nil)
    }

    @Test("isExpired reflects expiresAt relative to now")
    func expiry() {
        let expired = StoredToken(value: SecureBytes([1]), expiresAt: Date(timeIntervalSinceNow: -10))
        let future = StoredToken(value: SecureBytes([1]), expiresAt: Date(timeIntervalSinceNow: 1000))
        let never = StoredToken(value: SecureBytes([1]), expiresAt: nil)
        #expect(expired.isExpired)
        #expect(!future.isExpired)
        #expect(!never.isExpired)
    }

    @Test("a truncated representation throws rather than crashing")
    func truncated() {
        #expect(throws: (any Error).self) {
            _ = try StoredToken(secureBytes: SecureBytes([1, 2, 3]))
        }
    }
}
