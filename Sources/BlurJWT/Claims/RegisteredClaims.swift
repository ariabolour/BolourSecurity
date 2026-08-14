import Foundation

/// The standard registered claims (RFC 7519 §4.1).
public struct RegisteredClaims: JWTClaims {
    public var issuer: String?
    public var subject: String?
    public var audience: [String]?
    public var expiresAt: Date?
    public var notBefore: Date?
    public var issuedAt: Date?
    public var tokenID: String?

    public init(
        issuer: String? = nil, subject: String? = nil, audience: [String]? = nil,
        expiresAt: Date? = nil, notBefore: Date? = nil, issuedAt: Date? = nil, tokenID: String? = nil
    ) {
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.expiresAt = expiresAt
        self.notBefore = notBefore
        self.issuedAt = issuedAt
        self.tokenID = tokenID
    }

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiresAt = "exp"
        case notBefore = "nbf"
        case issuedAt = "iat"
        case tokenID = "jti"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        issuer = try container.decodeIfPresent(String.self, forKey: .issuer)
        subject = try container.decodeIfPresent(String.self, forKey: .subject)
        // RFC 7519 §4.1.3: "aud" is either a single string or an array of strings in the wild.
        // We only ever *produce* an array, but must accept either on the way in.
        if let audienceArray = try? container.decodeIfPresent([String].self, forKey: .audience) {
            audience = audienceArray
        } else {
            audience = (try container.decodeIfPresent(String.self, forKey: .audience)).map { [$0] }
        }
        expiresAt = try container.decodeIfPresent(Date.self, forKey: .expiresAt)
        notBefore = try container.decodeIfPresent(Date.self, forKey: .notBefore)
        issuedAt = try container.decodeIfPresent(Date.self, forKey: .issuedAt)
        tokenID = try container.decodeIfPresent(String.self, forKey: .tokenID)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(issuer, forKey: .issuer)
        try container.encodeIfPresent(subject, forKey: .subject)
        try container.encodeIfPresent(audience, forKey: .audience)
        try container.encodeIfPresent(expiresAt, forKey: .expiresAt)
        try container.encodeIfPresent(notBefore, forKey: .notBefore)
        try container.encodeIfPresent(issuedAt, forKey: .issuedAt)
        try container.encodeIfPresent(tokenID, forKey: .tokenID)
    }
}
