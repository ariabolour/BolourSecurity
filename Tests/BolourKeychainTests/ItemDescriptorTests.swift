import Testing
import Foundation
import Security
@testable import BolourKeychain
import BolourSecurityCore

@Suite("ItemDescriptor mapping")
struct ItemDescriptorTests {

    /// Exhaustive: every `ProtectionPolicy` maps to the expected `kSecAttrAccessible*` constant.
    /// (`CFString` is not `Sendable`, so this compares as `String` rather than parameterizing.)
    @Test("accessible mapping is exhaustive")
    func accessibleMapping() {
        func accessible(_ policy: ProtectionPolicy) -> String {
            ItemDescriptor.accessibleValue(for: policy) as String
        }
        #expect(accessible(.whenUnlocked(.thisDeviceOnly)) == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String))
        #expect(accessible(.whenUnlocked(.synchronizable)) == (kSecAttrAccessibleWhenUnlocked as String))
        #expect(accessible(.afterFirstUnlock(.thisDeviceOnly)) == (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String))
        #expect(accessible(.afterFirstUnlock(.synchronizable)) == (kSecAttrAccessibleAfterFirstUnlock as String))
        #expect(accessible(.whenPasscodeSet) == (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String))
    }

    @Test("presence maps to the right access-control flags")
    func accessControlFlags() {
        #expect(ItemDescriptor.accessControlFlags(for: .userPresence) == .userPresence)
        #expect(ItemDescriptor.accessControlFlags(for: .biometry(.currentSet)) == .biometryCurrentSet)
        #expect(ItemDescriptor.accessControlFlags(for: .biometry(.anyEnrolled)) == .biometryAny)
        #expect(ItemDescriptor.accessControlFlags(for: .devicePasscode) == .devicePasscode)
        #expect(ItemDescriptor.accessControlFlags(for: .none) == [])
    }

    @Test("only synchronizable policies opt into sync")
    func synchronizable() {
        #expect(descriptor(.whenUnlocked(.synchronizable)).isSynchronizable)
        #expect(descriptor(.afterFirstUnlock(.synchronizable)).isSynchronizable)
        #expect(descriptor(.whenUnlocked(.thisDeviceOnly)).isSynchronizable == false)
        #expect(descriptor(.whenPasscodeSet).isSynchronizable == false)
    }

    @Test("base query carries identity and the data-protection keychain")
    func baseQuery() {
        let query = ItemDescriptor(
            service: "svc", key: "account.key", accessGroup: "group.example",
            protection: .whenUnlocked(.synchronizable), presence: .none
        ).baseQuery()
        #expect(query[kSecClass] as! CFString == kSecClassGenericPassword)
        #expect(query[kSecAttrService] as? String == "svc")
        #expect(query[kSecAttrAccount] as? String == "account.key")
        #expect(query[kSecAttrAccessGroup] as? String == "group.example")
        #expect(query[kSecUseDataProtectionKeychain] as? Bool == true)
        #expect(query[kSecAttrSynchronizable] as? Bool == true)
    }

    @Test("no access group key when none is configured")
    func noAccessGroup() {
        let query = descriptor(.default).baseQuery()
        #expect(query[kSecAttrAccessGroup] == nil)
        #expect(query[kSecAttrSynchronizable] == nil)   // this-device-only default
    }

    @Test("protection attributes use accessible without presence, access-control with it")
    func protectionAttributes() throws {
        let plain = try descriptor(.default, presence: .none).protectionAttributes()
        #expect(plain[kSecAttrAccessible] != nil)
        #expect(plain[kSecAttrAccessControl] == nil)

        let gated = try descriptor(.default, presence: .biometry()).protectionAttributes()
        #expect(gated[kSecAttrAccessControl] != nil)
        #expect(gated[kSecAttrAccessible] == nil)
    }

    private func descriptor(
        _ protection: ProtectionPolicy, presence: PresenceRequirement = .none
    ) -> ItemDescriptor {
        ItemDescriptor(service: "svc", key: "k", accessGroup: nil, protection: protection, presence: presence)
    }
}
