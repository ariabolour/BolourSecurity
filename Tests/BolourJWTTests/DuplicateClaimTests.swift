import Testing
import Foundation
@testable import BolourJWT

/// `JSONDecoder` resolves a repeated member name by silently keeping the **last** value. Other
/// parsers keep the first. A token carrying both spellings therefore means different things to
/// this library and to whatever reads it next — a server, a proxy, an auditor — and that
/// disagreement is the attack. `UnverifiedJWT` refuses to produce such a token at all.
@Suite("Duplicate JSON keys are rejected before decoding")
struct DuplicateClaimTests {

    private func token(header: String, payload: String) -> String {
        "\(Base64URL.encode(Data(header.utf8))).\(Base64URL.encode(Data(payload.utf8))).sig"
    }

    private func malformation(_ serialization: String, sourceLocation: SourceLocation = #_sourceLocation) -> MalformationDetail? {
        do {
            _ = try UnverifiedJWT(compactSerialization: serialization)
            Issue.record("expected the token to be rejected", sourceLocation: sourceLocation)
            return nil
        } catch let JWTError.malformedToken(detail) {
            return detail
        } catch {
            Issue.record("expected malformedToken, got \(error)", sourceLocation: sourceLocation)
            return nil
        }
    }

    /// The headline case: `JSONDecoder` reads `ES256` and would verify happily, while a
    /// first-wins reader downstream sees `none`.
    @Test("a header repeating alg is rejected, whichever value JSONDecoder would have kept")
    func duplicateAlgorithm() {
        #expect(
            malformation(token(header: #"{"alg":"none","alg":"ES256"}"#, payload: "{}"))
                == .duplicateHeaderParameter(name: "alg")
        )
        #expect(
            malformation(token(header: #"{"alg":"ES256","alg":"none"}"#, payload: "{}"))
                == .duplicateHeaderParameter(name: "alg")
        )
    }

    @Test("every security-critical header parameter is covered", arguments: ["alg", "kid", "typ", "crit", "jku"])
    func duplicateHeaderParameters(name: String) {
        let header = #"{"alg":"ES256","\#(name)":"a","\#(name)":"b"}"#
        #expect(malformation(token(header: header, payload: "{}")) == .duplicateHeaderParameter(name: name))
    }

    @Test("every registered claim is covered", arguments: ["iss", "aud", "exp", "nbf", "iat", "jti", "sub", "nonce"])
    func duplicatePayloadClaims(name: String) {
        let payload = #"{"\#(name)":"a","\#(name)":"b"}"#
        #expect(
            malformation(token(header: #"{"alg":"ES256"}"#, payload: payload))
                == .duplicatePayloadClaim(name: name)
        )
    }

    /// Rejecting *any* repeat, not a curated list, is what covers the claims an app authorizes
    /// on — which this library has never heard of.
    @Test("an application-specific claim this library has never heard of is covered too")
    func duplicateUnknownClaim() {
        let detail = malformation(token(header: #"{"alg":"ES256"}"#, payload: #"{"tenant_role":"viewer","tenant_role":"admin"}"#))
        #expect(detail == .duplicatePayloadClaim(name: nil))
    }

    /// The name is matched against a fixed set, so an error can never carry token-chosen text.
    @Test("an unregistered duplicate name is never echoed back into the error")
    func unregisteredNamesAreNotEchoed() {
        let detail = malformation(token(header: #"{"alg":"ES256"}"#, payload: #"{"</script><script>":1,"</script><script>":2}"#))
        #expect(detail == .duplicatePayloadClaim(name: nil))
    }

    /// Comparing raw bytes rather than decoded names would let an attacker spell one half of a
    /// duplicated pair in JSON escapes and walk straight past the check. Built by concatenation
    /// so the backslashes are unambiguously *in the JSON*, not Swift-level escapes.
    @Test("escaped spellings of the same name still collide", arguments: 0..<3)
    func escapedNamesCollide(variant: Int) {
        let backslash = "\\"
        let escapedALG = backslash + "u0061" + "lg"                     // alg
        let fullyEscaped = backslash + "u0061" + backslash + "u006C" + "g"  // alg
        let spellings = [
            (escapedALG, "alg"),        // first key escaped
            ("alg", escapedALG),        // second key escaped
            (fullyEscaped, "alg"),      // every letter that can be escaped, escaped
        ]
        let (first, second) = spellings[variant]
        let header = "{\"\(first)\":\"none\",\"\(second)\":\"ES256\"}"
        #expect(header.contains(backslash), "the point of this test is a JSON-level escape")
        #expect(malformation(token(header: header, payload: "{}")) == .duplicateHeaderParameter(name: "alg"))
    }

    @Test("duplicates nested inside an object or array element are caught")
    func nestedDuplicates() {
        #expect(
            malformation(token(header: #"{"alg":"ES256"}"#, payload: #"{"ctx":{"role":"a","role":"b"}}"#))
                == .duplicatePayloadClaim(name: nil)
        )
        #expect(
            malformation(token(header: #"{"alg":"ES256"}"#, payload: #"{"list":[{"iss":1,"iss":2}]}"#))
                == .duplicatePayloadClaim(name: "iss")
        )
    }

    @Test("the same name in two sibling objects is not a duplicate")
    func siblingObjectsAreIndependent() throws {
        let serialization = token(
            header: #"{"alg":"ES256"}"#,
            payload: #"{"a":{"role":"x"},"b":{"role":"y"},"list":[{"n":1},{"n":2}]}"#
        )
        _ = try UnverifiedJWT(compactSerialization: serialization)
    }

    @Test("ordinary tokens with nesting, arrays, escapes, and numbers still parse")
    func wellFormedTokensStillParse() throws {
        let payload = #"""
        {"iss":"https://idp.example.com","aud":["a","b"],"exp":1893456000,"ratio":-1.5e3,
         "ok":true,"nothing":null,"nested":{"deep":{"deeper":[1,2,{"x":"y"}]}},
         "escaped":"quote:\" backslash:\\ slash:\/ tab:\t unicode:é pair:😀"}
        """#
        let parsed = try UnverifiedJWT(compactSerialization: token(header: #"{"alg":"ES256","kid":"k1"}"#, payload: payload))
        #expect(parsed.unverifiedHeader.algorithm == "ES256")
        #expect(parsed.unverifiedHeader.keyID == "k1")
    }

    /// The scanner defers to `JSONDecoder` on what valid JSON is, so unparseable input must still
    /// come back as an ordinary parse failure rather than a duplicate report.
    @Test("input the scanner can't parse falls through to the decoder's own error", arguments: [
        "not json at all", "{", #"{"alg":}"#, #"{"unterminated":"#, "[]", "null",
    ])
    func unscannableInputFallsThrough(header: String) {
        let detail = malformation(token(header: header, payload: "{}"))
        #expect(detail != nil)
        if case .duplicateHeaderParameter = detail { Issue.record("should not report a duplicate: \(header)") }
        if case .duplicatePayloadClaim = detail { Issue.record("should not report a duplicate: \(header)") }
    }

    @Test("deeply nested input is handled without recursing into a stack overflow")
    func deepNestingIsTotal() {
        // Well inside the 16 KiB segment cap, far past what recursive descent would survive.
        let depth = 2_000
        let payload = String(repeating: #"{"a":"#, count: depth) + "1" + String(repeating: "}", count: depth)
        // No duplicates anywhere in it, so the only requirement is that scanning terminates
        // without trapping — whether the decoder then accepts it is its own business.
        _ = try? UnverifiedJWT(compactSerialization: token(header: #"{"alg":"ES256"}"#, payload: payload))
    }

    @Test("a duplicate hidden at the bottom of a deeply nested payload is still found")
    func deepNestedDuplicateFound() {
        let depth = 500
        let payload = String(repeating: #"{"a":"#, count: depth)
            + #"{"iss":1,"iss":2}"#
            + String(repeating: "}", count: depth)
        #expect(
            malformation(token(header: #"{"alg":"ES256"}"#, payload: payload))
                == .duplicatePayloadClaim(name: "iss")
        )
    }

    @Test("byte-mutation sweep over a duplicate-bearing token never crashes")
    func mutationSweepNeverCrashes() {
        let serialization = token(header: #"{"alg":"none","alg":"ES256"}"#, payload: #"{"iss":"a","iss":"b"}"#)
        var bytes = Array(serialization.utf8)
        for index in bytes.indices {
            let original = bytes[index]
            bytes[index] = original == 0x41 ? 0x42 : 0x41
            _ = try? UnverifiedJWT(compactSerialization: String(decoding: bytes, as: UTF8.self))
            bytes[index] = original
        }
    }
}
