import Testing
import Foundation
import BolourSecurityCore

@Suite("SecretConvertible")
struct SecretConvertibleTests {

    /// A minimal reference conformance used to exercise the round-trip contract.
    struct Token: SecretConvertible, Equatable {
        var value: String

        init(value: String) { self.value = value }

        init(secureBytes: SecureBytes) throws {
            let data = secureBytes.dangerouslyExportBytes()
            guard let decoded = String(data: data, encoding: .utf8) else {
                throw TokenError.notUTF8
            }
            self.value = decoded
        }

        func secureBytesRepresentation() throws -> SecureBytes {
            SecureBytes(Array(value.utf8))
        }

        enum TokenError: Error { case notUTF8 }
    }

    @Test("round-trips through secure bytes")
    func roundTrip() throws {
        let token = Token(value: "hello-secret")
        let bytes = try token.secureBytesRepresentation()
        let restored = try Token(secureBytes: bytes)
        #expect(restored == token)
    }
}
