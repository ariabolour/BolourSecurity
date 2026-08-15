import Foundation

/// A server-minted nonce for one attestation attempt. Opaque here — `ServerChallenge` exists so
/// "I hashed my own timestamp" is visibly wrong at the call site; the module never accepts a
/// bare `Data` where a challenge is required.
public struct ServerChallenge: Sendable {
    let data: Data
    public init(_ data: Data) { self.data = data }
}
