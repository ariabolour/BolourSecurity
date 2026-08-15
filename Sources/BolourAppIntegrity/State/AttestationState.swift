import Foundation
import BolourSecurityCore

/// The persisted state machine. `invalidated` is reachable from any state (the OS can revoke a
/// key at any time); every other transition only ever moves forward.
enum AttestationState: Codable, Sendable, Equatable {
    case noKey
    case keyGenerated(keyID: String)
    case attested(keyID: String)
    case invalidated(keyID: String?)
}

extension AttestationState: SecretConvertible {
    init(secureBytes: SecureBytes) throws {
        self = try JSONDecoder().decode(AttestationState.self, from: secureBytes.dangerouslyExportBytes())
    }
    func secureBytesRepresentation() throws -> SecureBytes {
        SecureBytes(try JSONEncoder().encode(self))
    }
}
