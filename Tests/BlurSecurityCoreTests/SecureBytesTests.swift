import Testing
import Foundation
import BlurSecurityCore

@Suite("SecureBytes")
struct SecureBytesTests {

    @Test("init(count:) is zero-filled")
    func zeroFilled() {
        let bytes = SecureBytes(count: 32)
        #expect(bytes.count == 32)
        #expect(bytes.isEmpty == false)
        bytes.withUnsafeBytes { raw in
            #expect(raw.allSatisfy { $0 == 0 })
        }
    }

    @Test("an empty buffer reports empty")
    func empty() {
        let bytes = SecureBytes(count: 0)
        #expect(bytes.isEmpty)
        #expect(bytes.count == 0)
    }

    @Test("round-trips its contents")
    func roundTrip() {
        let original: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F]
        let bytes = SecureBytes(original)
        #expect(bytes.count == original.count)
        #expect(Array(bytes.dangerouslyExportBytes()) == original)
        bytes.withUnsafeBytes { raw in
            #expect(Array(raw) == original)
        }
    }

    @Test("equality is value-based")
    func equality() {
        #expect(SecureBytes([1, 2, 3]) == SecureBytes([1, 2, 3]))
        #expect(SecureBytes([1, 2, 3]) != SecureBytes([1, 2, 4]))
        #expect(SecureBytes([1, 2, 3]) != SecureBytes([1, 2]))
    }

    @Test("Hashable is consistent with equality")
    func hashing() {
        let a = SecureBytes([9, 8, 7])
        let b = SecureBytes([9, 8, 7])
        #expect(a.hashValue == b.hashValue)
        let set: Set<SecureBytes> = [a, b]
        #expect(set.count == 1)
    }

    @Test("descriptions never reveal contents")
    func redaction() {
        let secret = SecureBytes([0xAB, 0xCD, 0xEF])
        let described = String(describing: secret)
        let reflected = String(reflecting: secret)
        #expect(described.contains("redacted"))
        #expect(reflected.contains("redacted"))
        #expect(described.contains("3 bytes"))
        // No byte content in any spelling (hex or decimal).
        for needle in ["ab", "cd", "ef", "AB", "CD", "EF", "171", "205", "239"] {
            #expect(described.contains(needle) == false)
            #expect(reflected.contains(needle) == false)
        }
    }
}
