/// RFC 6749 §5.1 successful token response.
struct TokenEndpointResponse: Decodable {
    let accessToken: String
    let tokenType: String
    let expiresIn: Double?
    let refreshToken: String?
    let scope: String?
    let idToken: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
        case idToken = "id_token"
    }
}

/// RFC 6749 §5.2 error response.
struct TokenEndpointErrorResponse: Decodable {
    let error: String
}
