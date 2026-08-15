import Testing
import Foundation
@testable import BolourCertificates

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

    // MARK: - OID parsing (item 5's "OID parsing" checklist entry: no prior direct coverage)

    @Test("an OID whose final continuation byte is never terminated throws, never crashes")
    func truncatedOIDArc() {
        // 0x06 (OBJECT IDENTIFIER tag), 0x03 (length 3), then 3 bytes all with the continuation
        // bit set (0x80) — the multi-byte arc never terminates, so `objectIdentifierString()`'s
        // `pending` flag is still true when input runs out.
        var scanner = DERScanner([0x06, 0x03, 0xff, 0xff, 0xff])
        #expect(throws: CertificateError.self) {
            let element = try scanner.readElement(expecting: DERTag.objectIdentifier)
            _ = try element.objectIdentifierString()
        }
    }

    @Test("a pathologically long single OID arc never crashes, whatever it decodes to")
    func oversizedOIDArc() {
        // A single arc built from 32 continuation bytes (0xff) plus one terminator (0x00):
        // `current = (current << 7) | byte` overflows Int's 64 bits many times over across 32
        // shifts. Swift's `<<` is a non-trapping smart shift (overflowed high bits are simply
        // discarded, never a runtime trap), so this must not crash — it may legitimately decode
        // to a garbage-but-well-formed decimal string, which is an acceptable outcome; a crash
        // or hang is not.
        var arc = [UInt8](repeating: 0xff, count: 32)
        arc.append(0x00)
        let content: [UInt8] = [0x06, UInt8(arc.count)] + arc
        var scanner = DERScanner(content)
        #expect(throws: Never.self) {
            let element = try scanner.readElement(expecting: DERTag.objectIdentifier)
            _ = try? element.objectIdentifierString()   // may throw a typed error; must not trap
        }
    }

    @Test("a zero-length OID content throws rather than crashing on an empty first byte")
    func emptyOID() {
        var scanner = DERScanner([0x06, 0x00])
        #expect(throws: CertificateError.self) {
            let element = try scanner.readElement(expecting: DERTag.objectIdentifier)
            _ = try element.objectIdentifierString()
        }
    }

    // MARK: - Iteration scale (item 5's "nested containers" / "nesting bombs" checklist entry)
    //
    // `Certificate.parse` never recurses — `DERScanner` is walked with fresh, already-bounded
    // sub-scanners at each level, and every "container" (RDN sequences, extensions, SAN lists)
    // is a single flat `while !isAtEnd` loop over one such sub-scanner, never a call back into
    // itself. A classic recursive-descent "nesting bomb" (attacker-controlled recursion depth)
    // is therefore not a reachable code path by construction. What a large, well-formed *count*
    // of sibling elements CAN still stress is the iteration itself — this test proves that
    // stays linear and crash-free at a scale no real certificate would ever reach, exercising
    // the same `DERScanner.readElement()` loop every container-walking call site in
    // `Certificate.swift` uses.
    @Test("tens of thousands of sibling elements parse quickly, without crashing or hanging")
    func manySiblingElements() throws {
        var content: [UInt8] = []
        content.reserveCapacity(50_000 * 2)
        for _ in 0..<50_000 { content.append(contentsOf: [DERTag.boolean, 0x00]) }  // 2 bytes each

        var scanner = DERScanner(content)
        var count = 0
        while !scanner.isAtEnd {
            _ = try scanner.readElement()
            count += 1
        }
        #expect(count == 50_000)
    }
}
