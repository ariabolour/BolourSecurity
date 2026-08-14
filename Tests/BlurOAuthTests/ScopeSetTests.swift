import Testing
@testable import BlurOAuth

@Suite("ScopeSet")
struct ScopeSetTests {
    @Test("+ unions two scope sets")
    func union() {
        let combined = ScopeSet.openID + ["offline_access"]
        #expect(combined.spaceSeparated.contains("offline_access"))
        #expect(combined.spaceSeparated.contains("openid"))
    }
}
