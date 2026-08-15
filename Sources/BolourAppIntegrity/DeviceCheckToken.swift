import DeviceCheck
import Foundation

/// DeviceCheck: the lower-assurance sibling of App Attest. A device emits an opaque, ephemeral
/// token the server exchanges with Apple for two persistent bits — a fraud signal, not an
/// identity, and not a substitute for App Attest where it's available.
public enum DeviceCheckToken {
    public static var isSupported: Bool { DCDevice.current.isSupported }

    /// Generates a fresh ephemeral token for the server-side DeviceCheck query/update API.
    public static func generate() async throws(IntegrityError) -> Data {
        guard DCDevice.current.isSupported else {
            throw IntegrityError.unsupported(.platform)
        }
        do {
            return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                DCDevice.current.generateToken { data, error in
                    if let data {
                        continuation.resume(returning: data)
                    } else {
                        continuation.resume(throwing: error ?? DCError(.unknownSystemFailure))
                    }
                }
            }
        } catch let error as DCError {
            throw IntegrityError.attestationRejected(underlying: error)
        } catch {
            throw IntegrityError.underlying(UnknownAttestationFailure(description: "\(error)"))
        }
    }
}

struct UnknownAttestationFailure: Error, Sendable {
    let description: String
}
