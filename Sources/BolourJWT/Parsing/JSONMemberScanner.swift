import Foundation

/// Finds repeated member names in a JSON document.
///
/// **Why this exists.** RFC 8259 §4 says object member names "SHOULD be unique" — a SHOULD, not
/// a MUST — and leaves the behavior for duplicates to the implementation. `JSONDecoder` resolves
/// them by keeping the **last** value silently. Other parsers keep the first. A token like
/// `{"alg":"none","alg":"ES256"}` therefore *means different things* to different readers, and
/// that disagreement is the entire attack: this library sees `ES256` and verifies happily while
/// a first-wins server, proxy, or auditor reads `none`. The same trick applies to `iss`, `aud`,
/// `exp` — any claim someone downstream makes a decision on.
///
/// No decoder API exposes a duplicate-key policy, so detection has to happen on the raw bytes
/// before decoding. Every repeated name is rejected, at every nesting level, rather than a
/// curated list of "important" ones: an allowlist is a maintenance liability and would miss the
/// application-specific claims apps actually authorize on.
///
/// **Totality**, matching `BolourCertificates`' DER scanner: this never traps and never recurses.
/// Container nesting is tracked on an explicit stack, so a deeply nested document costs heap
/// proportional to its depth (itself bounded by `UnverifiedJWT`'s 16 KiB segment cap) rather
/// than risking a stack overflow. Anything it cannot parse returns ``Outcome/notScannable`` —
/// it defers to `JSONDecoder` on what valid JSON is instead of becoming a second, subtly
/// divergent validator that might reject tokens the decoder would accept.
enum JSONMemberScanner {

    enum Outcome: Equatable {
        /// No member name repeats anywhere in the document.
        case clean
        /// A member name repeats. Carries the name only when it is one of
        /// ``reportableNames`` — never attacker-chosen text.
        case duplicate(name: String?)
        /// Not parseable as JSON. The caller lets `JSONDecoder` report why.
        case notScannable
    }

    /// Member names safe to name in an error message, because membership is decided against
    /// this fixed set rather than by copying bytes out of the token. Covers the JOSE header
    /// parameters (RFC 7515 §4.1), the registered claims (RFC 7519 §4.1), and the OIDC claims
    /// this package itself reads.
    static let reportableNames: Set<String> = [
        "alg", "kid", "typ", "cty", "crit", "jku", "jwk", "x5u", "x5c", "x5t", "enc", "zip",
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
        "nonce", "azp", "scope", "at_hash", "c_hash", "auth_time", "acr", "amr",
    ]

    private enum Frame {
        case object(names: Set<String>)
        case array
    }

    private enum State {
        case value
        case arrayFirstValueOrClose
        case objectFirstKeyOrClose
        case objectKey
        case colon
        case commaOrClose
    }

    /// Converts to `[UInt8]` once rather than indexing the `Data` directly: a `Data`'s
    /// `startIndex` is not guaranteed to be 0, and integer-literal indexing into one is a live
    /// crash rather than a catchable throw. An array is always 0-indexed. (This bit the package
    /// twice already — see `VaultReadStream` and the JWK parser.)
    static func scan(_ data: Data) -> Outcome {
        scan([UInt8](data))
    }

    // swiftlint:disable:next cyclomatic_complexity function_body_length
    private static func scan(_ bytes: [UInt8]) -> Outcome {
        var index = 0
        var stack: [Frame] = []
        var state = State.value

        while true {
            skipWhitespace(bytes, &index)
            guard index < bytes.count else { return .notScannable }
            let byte = bytes[index]

            switch state {
            case .value, .arrayFirstValueOrClose:
                if state == .arrayFirstValueOrClose, byte == UInt8(ascii: "]") {
                    index += 1
                    guard case .array? = stack.popLast() else { return .notScannable }
                    if let outcome = afterValue(stack, bytes, index, &state) { return outcome }
                    continue
                }
                switch byte {
                case UInt8(ascii: "{"):
                    index += 1
                    stack.append(.object(names: []))
                    state = .objectFirstKeyOrClose
                case UInt8(ascii: "["):
                    index += 1
                    stack.append(.array)
                    state = .arrayFirstValueOrClose
                case UInt8(ascii: "\""):
                    guard parseString(bytes, &index) != nil else { return .notScannable }
                    if let outcome = afterValue(stack, bytes, index, &state) { return outcome }
                case UInt8(ascii: "t"), UInt8(ascii: "f"), UInt8(ascii: "n"):
                    guard consumeLiteral(bytes, &index) else { return .notScannable }
                    if let outcome = afterValue(stack, bytes, index, &state) { return outcome }
                case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
                    guard consumeNumber(bytes, &index) else { return .notScannable }
                    if let outcome = afterValue(stack, bytes, index, &state) { return outcome }
                default:
                    return .notScannable
                }

            case .objectFirstKeyOrClose, .objectKey:
                if state == .objectFirstKeyOrClose, byte == UInt8(ascii: "}") {
                    index += 1
                    guard case .object? = stack.popLast() else { return .notScannable }
                    if let outcome = afterValue(stack, bytes, index, &state) { return outcome }
                    continue
                }
                guard byte == UInt8(ascii: "\""), let name = parseString(bytes, &index) else {
                    return .notScannable
                }
                guard case .object(var names) = stack.last else { return .notScannable }
                guard names.insert(name).inserted else {
                    return .duplicate(name: reportableNames.contains(name) ? name : nil)
                }
                stack[stack.count - 1] = .object(names: names)
                state = .colon

            case .colon:
                guard byte == UInt8(ascii: ":") else { return .notScannable }
                index += 1
                state = .value

            case .commaOrClose:
                switch byte {
                case UInt8(ascii: ","):
                    index += 1
                    switch stack.last {
                    case .object: state = .objectKey
                    case .array: state = .value
                    case nil: return .notScannable
                    }
                case UInt8(ascii: "}"):
                    index += 1
                    guard case .object? = stack.popLast() else { return .notScannable }
                    if let outcome = afterValue(stack, bytes, index, &state) { return outcome }
                case UInt8(ascii: "]"):
                    index += 1
                    guard case .array? = stack.popLast() else { return .notScannable }
                    if let outcome = afterValue(stack, bytes, index, &state) { return outcome }
                default:
                    return .notScannable
                }
            }
        }
    }

    /// Called once a complete value has been consumed. Returns a final outcome when that value
    /// closed the top level, and otherwise moves to `commaOrClose` inside the enclosing container.
    private static func afterValue(
        _ stack: [Frame], _ bytes: [UInt8], _ index: Int, _ state: inout State
    ) -> Outcome? {
        guard stack.isEmpty else {
            state = .commaOrClose
            return nil
        }
        var trailing = index
        skipWhitespace(bytes, &trailing)
        return trailing == bytes.count ? .clean : .notScannable
    }

    private static func skipWhitespace(_ bytes: [UInt8], _ index: inout Int) {
        while index < bytes.count {
            switch bytes[index] {
            case 0x20, 0x09, 0x0A, 0x0D: index += 1
            default: return
            }
        }
    }

    /// Parses a JSON string at `index`, leaving `index` just past the closing quote.
    ///
    /// Returns the **decoded** value, not the raw span: `"alg"` and `"alg"` are the same
    /// member name to any conforming parser, so comparing raw bytes would let an attacker spell
    /// one of a duplicated pair in escapes and slip straight through this check.
    private static func parseString(_ bytes: [UInt8], _ index: inout Int) -> String? {
        guard index < bytes.count, bytes[index] == UInt8(ascii: "\"") else { return nil }
        index += 1
        var decoded: [UInt8] = []

        while index < bytes.count {
            let byte = bytes[index]
            switch byte {
            case UInt8(ascii: "\""):
                index += 1
                return String(decoding: decoded, as: UTF8.self)
            case UInt8(ascii: "\\"):
                index += 1
                guard index < bytes.count else { return nil }
                let escape = bytes[index]
                index += 1
                switch escape {
                case UInt8(ascii: "\""): decoded.append(UInt8(ascii: "\""))
                case UInt8(ascii: "\\"): decoded.append(UInt8(ascii: "\\"))
                case UInt8(ascii: "/"): decoded.append(UInt8(ascii: "/"))
                case UInt8(ascii: "b"): decoded.append(0x08)
                case UInt8(ascii: "f"): decoded.append(0x0C)
                case UInt8(ascii: "n"): decoded.append(0x0A)
                case UInt8(ascii: "r"): decoded.append(0x0D)
                case UInt8(ascii: "t"): decoded.append(0x09)
                case UInt8(ascii: "u"):
                    guard let scalar = parseUnicodeEscape(bytes, &index) else { return nil }
                    decoded.append(contentsOf: Array(String(scalar).utf8))
                default:
                    return nil
                }
            case 0x00...0x1F:
                return nil                      // RFC 8259 §7: unescaped control characters.
            default:
                decoded.append(byte)
                index += 1
            }
        }
        return nil                              // Unterminated.
    }

    /// Parses the four hex digits after `\u`, joining a surrogate pair when one follows.
    /// `index` points just past the `u` on entry and just past the last consumed digit on exit.
    private static func parseUnicodeEscape(_ bytes: [UInt8], _ index: inout Int) -> Unicode.Scalar? {
        guard let first = parseHexQuad(bytes, &index) else { return nil }

        if (0xD800...0xDBFF).contains(first) {
            // A high surrogate is only meaningful paired with the low surrogate that follows.
            guard index + 1 < bytes.count,
                  bytes[index] == UInt8(ascii: "\\"), bytes[index + 1] == UInt8(ascii: "u")
            else { return nil }
            var lookahead = index + 2
            guard let second = parseHexQuad(bytes, &lookahead), (0xDC00...0xDFFF).contains(second) else {
                return nil
            }
            index = lookahead
            let combined = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            return Unicode.Scalar(combined)
        }
        // A lone low surrogate is not a scalar; `Unicode.Scalar.init` rejects it for us.
        return Unicode.Scalar(first)
    }

    private static func parseHexQuad(_ bytes: [UInt8], _ index: inout Int) -> UInt32? {
        guard index + 4 <= bytes.count else { return nil }
        var value: UInt32 = 0
        for offset in 0..<4 {
            guard let digit = hexValue(bytes[index + offset]) else { return nil }
            value = value << 4 | UInt32(digit)
        }
        index += 4
        return value
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
        default: return nil
        }
    }

    private static func consumeLiteral(_ bytes: [UInt8], _ index: inout Int) -> Bool {
        for literal in ["true", "false", "null"] {
            let expected = Array(literal.utf8)
            guard index + expected.count <= bytes.count,
                  Array(bytes[index..<(index + expected.count)]) == expected
            else { continue }
            index += expected.count
            return true
        }
        return false
    }

    /// Consumes the run of characters a JSON number can be made of. Deliberately does not
    /// validate the grammar — `JSONDecoder` is the authority on that, and this only needs to
    /// know where the number ends so scanning can continue.
    private static func consumeNumber(_ bytes: [UInt8], _ index: inout Int) -> Bool {
        let start = index
        while index < bytes.count {
            switch bytes[index] {
            case UInt8(ascii: "0")...UInt8(ascii: "9"),
                 UInt8(ascii: "-"), UInt8(ascii: "+"), UInt8(ascii: "."),
                 UInt8(ascii: "e"), UInt8(ascii: "E"):
                index += 1
            default:
                return index > start
            }
        }
        return index > start
    }
}
