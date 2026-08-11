import Testing
import Foundation
import BlurCrypto
import BlurSecurityCore

@Suite("Key derivation")
struct KeyDerivationTests {

    @Test("HKDF-SHA256 matches RFC 5869 test case 1")
    func hkdfKnownAnswer() {
        let ikm = SecureBytes(Array(repeating: UInt8(0x0b), count: 22))
        let salt = Data((0x00...0x0c).map { UInt8($0) })
        let info = Data((0xf0...0xf9).map { UInt8($0) })
        let okm = KeyDerivation.hkdf(from: ikm, salt: salt, info: info, outputByteCount: 42)
        #expect(okm.dangerouslyExportBytes()
            == hexData("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
    }

    @Test("PBKDF2-HMAC-SHA256 known-answer and determinism")
    func pbkdf2KnownAnswer() throws {
        let parameters = PasswordHashingParameters(iterations: 100_000, outputByteCount: 32)
        let derived = try KeyDerivation.fromPassword("password", salt: Data("salt".utf8), parameters: parameters)
        #expect(derived.dangerouslyExportBytes()
            == hexData("0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5"))

        let again = try KeyDerivation.fromPassword("password", salt: Data("salt".utf8), parameters: parameters)
        #expect(again == derived)
    }

    @Test("iteration counts below the floor are rejected")
    func floorEnforced() {
        #expect(throws: CryptoError.self) {
            _ = try KeyDerivation.fromPassword(
                "pw", salt: Data("salt".utf8),
                parameters: PasswordHashingParameters(iterations: 1_000)
            )
        }
    }
}
