import Foundation
@testable import BlurKeychain
import BlurSecurityCore

/// Probes, once, whether this environment can actually read/write the keychain — same
/// constraint and same gating pattern as `BlurKeychainTests.KeychainProbe`: live SecItem
/// round-trips can't run in hostless `swift test` bundles on any platform.
enum KeychainProbe {
    static let isAvailable: Bool = {
        let keychain = Keychain(service: "BlurSecureStorage.keychain-probe")
        let key: ItemKey = "probe"
        do {
            try keychain.synchronouslyStore(SecureBytes([0x01]), for: key, presence: .none)
            try? keychain.synchronouslyDelete(for: key)
            return true
        } catch {
            return false
        }
    }()
}
