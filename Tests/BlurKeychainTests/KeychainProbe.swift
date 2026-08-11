import Foundation
@testable import BlurKeychain
import BlurSecurityCore

/// Probes, once, whether this environment can actually read/write the keychain the library uses
/// here — exercising the real `Keychain` code path so the gate matches library behavior exactly.
///
/// Where it cannot (e.g. a locked login keychain in headless CI, or a macOS build that forces the
/// entitlement-gated data-protection keychain), the integration suites are skipped (not failed) —
/// matching the spec's tiering, in which real-keychain round-trips are environment-gated — while
/// the pure descriptor-mapping suites remain the always-green floor.
enum KeychainProbe {
    static let isAvailable: Bool = {
        let keychain = Keychain(service: "BlurSecurity.keychain-probe")
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
