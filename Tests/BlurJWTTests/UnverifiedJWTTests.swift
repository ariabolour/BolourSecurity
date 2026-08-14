import Testing
import Foundation
@testable import BlurJWT

@Suite("UnverifiedJWT parsing — malformed input always throws, never crashes")
struct UnverifiedJWTTests {

    @Test(
        "wrong segment counts are rejected",
        arguments: ["", "a", "a.b", "a.b.c.d", "....", "a.b.c.d.e"]
    )
    func wrongSegmentCount(_ token: String) {
        #expect(throws: JWTError.self) {
            _ = try UnverifiedJWT(compactSerialization: token)
        }
    }

    @Test("invalid base64url in any segment is rejected")
    func invalidBase64() {
        #expect(throws: JWTError.self) {
            _ = try UnverifiedJWT(compactSerialization: "not!valid!base64.eyJhIjoxfQ.sig")
        }
    }

    @Test("a header that isn't JSON is rejected")
    func headerNotJSON() {
        let header = Base64URL.encode(Data("not json".utf8))
        let payload = Base64URL.encode(Data("{}".utf8))
        #expect(throws: JWTError.self) {
            _ = try UnverifiedJWT(compactSerialization: "\(header).\(payload).sig")
        }
    }

    @Test("a header missing alg is rejected")
    func headerMissingAlgorithm() {
        let header = Base64URL.encode(Data("{\"typ\":\"JWT\"}".utf8))
        let payload = Base64URL.encode(Data("{}".utf8))
        #expect(throws: JWTError.self) {
            _ = try UnverifiedJWT(compactSerialization: "\(header).\(payload).sig")
        }
    }

    @Test("an oversized segment is rejected before any decoding")
    func oversizedSegment() {
        let huge = String(repeating: "A", count: 20 * 1024)
        #expect(throws: JWTError.self) {
            _ = try UnverifiedJWT(compactSerialization: "\(huge).eyJhIjoxfQ.sig")
        }
    }

    @Test("the classic alg: none token structurally parses but never verifies")
    func algNoneParsesButNeverVerifies() throws {
        let header = Base64URL.encode(Data("{\"alg\":\"none\",\"typ\":\"JWT\"}".utf8))
        let payload = Base64URL.encode(Data("{\"iss\":\"evil\",\"aud\":[\"com.example.app\"]}".utf8))
        // No third segment content needed — the empty string base64url-decodes to empty Data.
        let token = try UnverifiedJWT(compactSerialization: "\(header).\(payload).")
        #expect(token.unverifiedHeader.algorithm == "none")
        // Parsing succeeds (it's structurally valid); there is still no claims accessor here —
        // JWTVerifier is exercised separately to prove it actually rejects "none".
    }

    @Test("deterministic mutation sweep: flipping any single byte of a valid token either still parses or throws — never crashes")
    func mutationSweepNeverCrashes() {
        let base = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0.eyJpc3MiOiJhIiwiYXVkIjpbImIiXX0.c2ln"
        var bytes = Array(base.utf8)
        for index in bytes.indices {
            let original = bytes[index]
            bytes[index] = original == 0x41 ? 0x42 : 0x41 // 'A' <-> 'B', stays ASCII/base64url-alphabet-adjacent
            let mutated = String(decoding: bytes, as: UTF8.self)
            _ = try? UnverifiedJWT(compactSerialization: mutated) // must not crash regardless of outcome
            bytes[index] = original
        }
    }
}
