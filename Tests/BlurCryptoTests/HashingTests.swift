import Testing
import Foundation
import BlurCrypto
import BlurSecurityCore

@Suite("Hashing")
struct HashingTests {

    @Test("SHA-2 known-answer vectors")
    func shaKnownAnswers() {
        #expect(SHA256.digest(of: Data("abc".utf8)).description
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(SHA256.digest(of: Data()).description
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        #expect(SHA384.digest(of: Data("abc".utf8)).description
            == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        #expect(SHA512.digest(of: Data("abc".utf8)).description
            == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    }

    @Test("streaming file digest matches the in-memory digest")
    func streamingMatchesInMemory() async throws {
        let data = Data((0..<200_000).map { UInt8($0 & 0xff) })
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("blur-hash-\(UUID().uuidString).bin")
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let streamed = try await SHA256.digest(ofFileAt: url)
        #expect(streamed == SHA256.digest(of: data))
    }

    @Test("an unreadable file throws fileUnreadable")
    func unreadableFile() async {
        let url = URL(fileURLWithPath: "/nonexistent/\(UUID().uuidString).bin")
        await #expect(throws: CryptoError.self) {
            _ = try await SHA256.digest(ofFileAt: url)
        }
    }

    @Test("HMAC-SHA256 known-answer and constant-time validation")
    func hmac() throws {
        let key = try SymmetricKey(secureBytes: SecureBytes(Array(repeating: UInt8(0x0b), count: 32)))
        let message = Data("Hi There".utf8)
        let code = HMAC<SHA256>.code(for: message, using: key)

        #expect(code.description == "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7")
        #expect(HMAC<SHA256>.isValidCode(code, for: message, using: key))
        #expect(HMAC<SHA256>.isValidCode(code, for: Data("Bye There".utf8), using: key) == false)
    }
}
