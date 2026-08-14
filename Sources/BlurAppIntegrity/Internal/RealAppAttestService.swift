import DeviceCheck
import Foundation

/// The real `AppAttestServicing` conformer: a thin async bridge over `DCAppAttestService`'s
/// completion-handler API. `DCAppAttestService.shared` is itself documented as safe to use from
/// any queue, so no locking is needed here (unlike `LAContext`/`SecureSessionDelegate`'s
/// `@unchecked Sendable` boxes for genuinely non-thread-safe platform objects).
struct RealAppAttestService: AppAttestServicing {
    var isSupported: Bool { DCAppAttestService.shared.isSupported }

    func generateKey() async throws(DCError) -> String {
        try await bridge { DCAppAttestService.shared.generateKey(completionHandler: $0) }
    }

    func attestKey(_ keyID: String, clientDataHash: Data) async throws(DCError) -> Data {
        try await bridge { DCAppAttestService.shared.attestKey(keyID, clientDataHash: clientDataHash, completionHandler: $0) }
    }

    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws(DCError) -> Data {
        try await bridge { DCAppAttestService.shared.generateAssertion(keyID, clientDataHash: clientDataHash, completionHandler: $0) }
    }

    /// Bridges a `(Result?, Error?) -> Void` completion handler to typed-throws async, matching
    /// the completion-handler ↔ async bridge pattern already used for `LAContext`/`SecureSessionDelegate`.
    private func bridge<Result: Sendable>(
        _ operation: (@escaping @Sendable (Result?, (any Error)?) -> Void) -> Void
    ) async throws(DCError) -> Result {
        do {
            return try await withCheckedThrowingContinuation { continuation in
                operation { value, error in
                    if let value {
                        continuation.resume(returning: value)
                    } else {
                        continuation.resume(throwing: error ?? DCError(.unknownSystemFailure))
                    }
                }
            }
        } catch let error as DCError {
            throw error
        } catch {
            throw DCError(.unknownSystemFailure)
        }
    }
}
