import Foundation

/// A JWS header. Structural only — presence here confers no trust; `unverifiedHeader`'s name is
/// the warning.
public struct JWTHeader: Sendable, Hashable {
    public let algorithm: String
    public let keyID: String?
    public let type: String?

    enum CodingKeys: String, CodingKey {
        case algorithm = "alg"
        case keyID = "kid"
        case type = "typ"
    }
}

extension JWTHeader: Codable {}
