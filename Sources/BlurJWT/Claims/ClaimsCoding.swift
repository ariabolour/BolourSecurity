import Foundation

/// The encoder/decoder every claims payload in this module goes through, so every `Date` field
/// — `RegisteredClaims`' own, and any embedded in an app-defined `JWTClaims` type — round-trips
/// as RFC 7519 `NumericDate` (Unix-epoch seconds) instead of Foundation's default
/// reference-date encoding.
enum ClaimsCoding {
    static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}

extension Date {
    /// Truncated (never rounded up) to whole seconds — RFC 7519 `NumericDate` values this
    /// module produces never carry sub-second precision, so the wire form is stable regardless
    /// of exactly when `Date()` was sampled.
    var truncatedToSeconds: Date {
        Date(timeIntervalSince1970: timeIntervalSince1970.rounded(.towardZero))
    }
}
