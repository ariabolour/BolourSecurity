import DeviceCheck
import Foundation

/// An internal seam around `DCAppAttestService`, so `AttestationService` can be driven by a
/// scripted double in tests — covering every state-machine transition and every `DCError` code
/// exhaustively — without App Attest hardware or entitlement.
protocol AppAttestServicing: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws(DCError) -> String
    func attestKey(_ keyID: String, clientDataHash: Data) async throws(DCError) -> Data
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws(DCError) -> Data
}
