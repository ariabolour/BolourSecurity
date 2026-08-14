import Foundation
@testable import BlurCrypto

/// Probes, once, whether this environment can actually create a Secure Enclave key — the same
/// hostless-keychain-style constraint `BlurKeychainTests.KeychainProbe` documents: `swift test`
/// (and simulator xctest) run as an unentitled host process, so `SecKeyCreateRandomKey` with
/// `kSecAttrTokenIDSecureEnclave` fails with `errSecMissingEntitlement` (-34018) regardless of
/// the hardware actually having a Secure Enclave.
enum SecureEnclaveProbe {
    static let isAvailable: Bool = {
        let tag = "BlurCrypto.secure-enclave-probe.\(UUID().uuidString)"
        guard let key = try? SecureEnclaveKey.create(tag: tag) else { return false }
        try? key.destroy()
        return true
    }()
}
