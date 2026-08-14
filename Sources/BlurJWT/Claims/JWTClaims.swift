/// A JWT claims set. Conform your own `Codable` struct to carry app-defined claims alongside
/// (or instead of) ``RegisteredClaims``.
///
/// - Note: Encode/decode `Date` fields with `JSONEncoder`/`JSONDecoder`'s `.secondsSince1970`
///   strategy — the module's own encoder/decoder always uses it, so every claims type's dates
///   round-trip as RFC 7519 `NumericDate` (Unix-epoch seconds), not Foundation's default
///   reference-date encoding.
public protocol JWTClaims: Codable, Sendable {}
