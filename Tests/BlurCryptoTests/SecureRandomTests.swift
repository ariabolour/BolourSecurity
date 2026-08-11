import Testing
import Foundation
import BlurCrypto

@Suite("SecureRandom")
struct SecureRandomTests {

    @Test("returns the requested number of bytes")
    func count() {
        #expect(SecureRandom.bytes(count: 16).count == 16)
        #expect(SecureRandom.data(count: 48).count == 48)
        #expect(SecureRandom.data(count: 0).isEmpty)
    }

    @Test("successive draws differ")
    func distinct() {
        #expect(SecureRandom.data(count: 32) != SecureRandom.data(count: 32))
    }

    @Test("number(in:) stays within range")
    func withinRange() {
        for _ in 0..<1_000 {
            let value = SecureRandom.number(in: 0..<10)
            #expect((0..<10).contains(value))
        }
    }

    @Test("number(in:) eventually covers a small range")
    func coversRange() {
        var seen = Set<Int>()
        for _ in 0..<2_000 { seen.insert(SecureRandom.number(in: 0..<6)) }
        #expect(seen == Set(0..<6))
    }
}
