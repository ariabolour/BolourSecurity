import Testing
import BlurSecurityCore

@Suite("Protection vocabulary")
struct ProtectionPolicyTests {

    @Test("default is whenUnlocked, this-device-only")
    func defaultPolicy() {
        #expect(ProtectionPolicy.default == .whenUnlocked(.thisDeviceOnly))
        #expect(ProtectionPolicy.whenUnlocked() == .whenUnlocked(.thisDeviceOnly))
        #expect(ProtectionPolicy.afterFirstUnlock() == .afterFirstUnlock(.thisDeviceOnly))
    }

    @Test("policies are distinct and Hashable")
    func distinctness() {
        let policies: Set<ProtectionPolicy> = [
            .whenUnlocked(.thisDeviceOnly),
            .whenUnlocked(.synchronizable),
            .afterFirstUnlock(.thisDeviceOnly),
            .whenPasscodeSet,
        ]
        #expect(policies.count == 4)
    }

    @Test("biometry() defaults to the current set")
    func biometryDefault() {
        #expect(PresenceRequirement.biometry() == .biometry(.currentSet))
        #expect(PresenceRequirement.biometry() != .biometry(.anyEnrolled))
    }

    @Test("presence requirements are distinct")
    func presenceDistinct() {
        let requirements: Set<PresenceRequirement> = [
            .none, .userPresence, .devicePasscode,
            .biometry(.currentSet), .biometry(.anyEnrolled),
        ]
        #expect(requirements.count == 5)
    }
}
