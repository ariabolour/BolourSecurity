import DeviceCheck
import Foundation
@testable import BolourAppIntegrity

/// A scripted `AppAttestServicing` double — every `AttestationService` state transition and
/// every `DCError` code is driven through this, never real App Attest hardware.
final class FakeAppAttestServicing: AppAttestServicing, @unchecked Sendable {
    private let lock = NSLock()

    var isSupported = true
    var generateKeyResult: Result<String, DCError> = .success("fake-key-id")
    var attestKeyResult: Result<Data, DCError> = .success(Data("attestation".utf8))
    var generateAssertionResult: Result<Data, DCError> = .success(Data("assertion".utf8))

    private var _generateKeyCallCount = 0
    private var _attestedKeyIDs: [String] = []
    private var _assertedKeyIDs: [String] = []

    var generateKeyCallCount: Int { withLock { _generateKeyCallCount } }
    var attestedKeyIDs: [String] { withLock { _attestedKeyIDs } }
    var assertedKeyIDs: [String] { withLock { _assertedKeyIDs } }

    /// `NSLock.lock()`/`unlock()` are unavailable directly inside `async` function bodies
    /// (priority-inversion-prone locking); this synchronous helper is not itself `async`, so
    /// calling it from an async context is unrestricted.
    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    func generateKey() async throws(DCError) -> String {
        withLock { _generateKeyCallCount += 1 }
        switch generateKeyResult {
        case .success(let keyID): return keyID
        case .failure(let error): throw error
        }
    }

    func attestKey(_ keyID: String, clientDataHash: Data) async throws(DCError) -> Data {
        withLock { _attestedKeyIDs.append(keyID) }
        switch attestKeyResult {
        case .success(let data): return data
        case .failure(let error): throw error
        }
    }

    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws(DCError) -> Data {
        withLock { _assertedKeyIDs.append(keyID) }
        switch generateAssertionResult {
        case .success(let data): return data
        case .failure(let error): throw error
        }
    }
}
