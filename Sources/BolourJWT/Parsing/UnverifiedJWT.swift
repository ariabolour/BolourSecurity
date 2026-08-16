import Foundation

/// A JWT that has been structurally parsed but not cryptographically verified.
///
/// There is deliberately **no claims accessor here.** Reading claims before verification is the
/// single most common JWT vulnerability class; `UnverifiedJWT` can't produce claims no matter
/// how it's used. `unverifiedHeader` exists (the algorithm and key ID are needed to *select* a
/// verification key) and its name is a standing warning at every call site that reads it.
public struct UnverifiedJWT: Sendable {
    public let unverifiedHeader: JWTHeader

    let headerSegment: Data
    let payloadSegment: Data
    let decodedPayload: Data
    let signature: Data

    /// The bytes that were actually signed: `base64url(header) ‖ "." ‖ base64url(payload)`.
    var signingInput: Data {
        var input = headerSegment
        input.append(UInt8(ascii: "."))
        input.append(payloadSegment)
        return input
    }

    /// A hostile token is the assumed input: segment count and size are checked before any
    /// base64 decoding or JSON parsing happens.
    private static let maximumSegmentLength = 16 * 1024

    public init(compactSerialization: String) throws(JWTError) {
        let parts = compactSerialization.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw JWTError.malformedToken(detail: .wrongSegmentCount(parts.count))
        }
        guard parts.allSatisfy({ $0.utf8.count <= UnverifiedJWT.maximumSegmentLength }) else {
            throw JWTError.malformedToken(detail: .segmentTooLarge)
        }

        guard let headerData = Base64URL.decode(parts[0]),
              let payloadData = Base64URL.decode(parts[1]),
              let signatureData = Base64URL.decode(parts[2])
        else {
            throw JWTError.malformedToken(detail: .invalidBase64)
        }

        // Before any decoding: `JSONDecoder` resolves a repeated member name by silently keeping
        // the last value, which makes a token with duplicates mean one thing here and something
        // else to a first-wins reader downstream. Both segments are screened, and the payload is
        // screened here rather than at `verify` time so no caller can reach an ambiguous token
        // through any path. See `JSONMemberScanner`.
        if case .duplicate(let name) = JSONMemberScanner.scan(headerData) {
            throw JWTError.malformedToken(detail: .duplicateHeaderParameter(name: name))
        }
        if case .duplicate(let name) = JSONMemberScanner.scan(payloadData) {
            throw JWTError.malformedToken(detail: .duplicatePayloadClaim(name: name))
        }

        let header: JWTHeader
        do {
            header = try JSONDecoder().decode(JWTHeader.self, from: headerData)
        } catch {
            throw JWTError.malformedToken(detail: .headerNotJSON)
        }
        guard !header.algorithm.isEmpty else {
            throw JWTError.malformedToken(detail: .headerMissingAlgorithm)
        }

        self.unverifiedHeader = header
        // Store the original (still-encoded) segments, not the decoded bytes: the signing input
        // is defined over the base64url text, and re-encoding after decoding is not guaranteed
        // to round-trip byte-for-byte (padding, alternate encodings of the same value).
        self.headerSegment = Data(parts[0].utf8)
        self.payloadSegment = Data(parts[1].utf8)
        self.decodedPayload = payloadData
        self.signature = signatureData
    }
}
