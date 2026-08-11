import Testing
import Foundation
import BlurCertificates

/// The headline invariant: the DER reader is total — every malformed input throws a typed
/// `CertificateError`, and nothing ever crashes, hangs, or over-allocates.
@Suite("DER parser is total")
struct DERFuzzTests {

    @Test("every truncation of a valid certificate throws")
    func truncations() throws {
        let der = [UInt8](try Fixture.der("leaf-valid"))
        for length in 0..<der.count {
            #expect(throws: CertificateError.self) {
                _ = try Certificate(derEncoded: Data(der[0..<length]))
            }
        }
    }

    @Test("a curated malformed corpus throws, never crashes")
    func malformedCorpus() {
        let corpus: [[UInt8]] = [
            [],                                   // empty
            [0x30],                               // tag only
            [0x30, 0x82],                         // long-form length header, no length bytes
            [0x30, 0x84, 0xff, 0xff, 0xff, 0xff], // absurd length
            [0x30, 0x80, 0x00, 0x00],             // indefinite length (illegal in DER)
            [0x02, 0x01, 0x00],                   // an INTEGER, not a certificate SEQUENCE
            [0x30, 0x03, 0x30, 0x01],             // inner length lies past the buffer
            Array(repeating: 0x30, count: 64),    // nesting-ish garbage
        ]
        for input in corpus {
            #expect(throws: CertificateError.self) {
                _ = try Certificate(derEncoded: Data(input))
            }
        }
    }

    @Test("single-byte mutations never crash and the pristine cert still parses")
    func byteFlips() throws {
        let original = [UInt8](try Fixture.der("leaf-valid"))
        // Deterministic sweep: flip the high bit of every byte, one at a time.
        for index in original.indices {
            var mutated = original
            mutated[index] ^= 0x80
            _ = try? Certificate(derEncoded: Data(mutated))   // must return or throw — never crash
        }
        #expect(throws: Never.self) { _ = try Certificate(derEncoded: Data(original)) }
    }
}
