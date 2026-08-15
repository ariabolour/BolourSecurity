import Foundation
import BolourSecurityCore

/// What `TokenManager` actually persists through the `SecretStore` seam — access + refresh
/// token together, so rotation can atomically replace both in one write.
struct StoredTokenSet: Codable, Sendable {
    let accessToken: String
    let refreshToken: String?
    let expiresAt: Date?
    let tokenType: String
    let scope: String?
}

extension StoredTokenSet: SecretConvertible {
    init(secureBytes: SecureBytes) throws {
        self = try JSONDecoder().decode(StoredTokenSet.self, from: secureBytes.dangerouslyExportBytes())
    }
    func secureBytesRepresentation() throws -> SecureBytes {
        SecureBytes(try JSONEncoder().encode(self))
    }
}
