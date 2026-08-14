import Foundation
import BlurSecurityCore

extension ProtectionPolicy {
    /// The `FileProtectionType` `Vault` applies to every artifact it writes.
    ///
    /// - Note: **Honest limit.** `FileProtectionType` has no analog of Keychain's "exists only
    ///   while a passcode is set, removed by the OS if the passcode is removed" semantics —
    ///   `.whenPasscodeSet` maps to `.complete`, the strongest available class, rather than a
    ///   non-existent exact equivalent.
    var fileProtectionType: FileProtectionType {
        switch self {
        case .whenUnlocked:
            return .complete
        case .afterFirstUnlock:
            return .completeUntilFirstUserAuthentication
        case .whenPasscodeSet:
            return .complete
        }
    }
}
