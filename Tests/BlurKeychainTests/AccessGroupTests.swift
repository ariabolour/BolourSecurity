import Testing
import BlurKeychain

@Suite("AccessGroup")
struct AccessGroupTests {

    @Test("factories and literals resolve to the same raw value")
    func factories() {
        #expect(AccessGroup.appGroup("group.com.example").rawValue == "group.com.example")
        #expect(AccessGroup.team("ABCDE12345.com.example").rawValue == "ABCDE12345.com.example")
        let literal: AccessGroup = "group.com.example"
        #expect(literal == .appGroup("group.com.example"))
    }
}
