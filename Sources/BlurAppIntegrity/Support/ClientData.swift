import Foundation
import BlurCrypto

/// The data a per-request assertion proves possession over — typically a hash binding the
/// request body to a server-issued nonce, so a captured assertion can't be replayed against a
/// different request.
public struct ClientData: Sendable {
    let hash: Digest256

    /// Hashes `requestBody ‖ serverNonce` with SHA-256. Baking the nonce into the hash (rather
    /// than sending it alongside) is what the server-side guide verifies against.
    public init(hashing requestBody: some DataProtocol, serverNonce: Data) {
        var combined = Data(requestBody)
        combined.append(serverNonce)
        self.hash = SHA256.digest(of: combined)
    }

    /// For callers that already computed the hash (e.g. to hash once and derive both a network
    /// request signature and an assertion from it).
    public init(precomputedHash: Digest256) {
        self.hash = precomputedHash
    }

    var hashData: Data { hash.withUnsafeBytes { Data($0) } }
}
