import Testing
import BlurSecurityCore

@Suite("ItemKey")
struct ItemKeyTests {

    @Test("string literal and explicit init agree")
    func agreement() {
        let literal: ItemKey = "auth.refresh-token"
        let explicit = ItemKey("auth.refresh-token")
        #expect(literal == explicit)
        #expect(literal.rawValue == "auth.refresh-token")
    }

    @Test("distinct keys are unequal")
    func distinct() {
        #expect(ItemKey("a") != ItemKey("b"))
    }
}
