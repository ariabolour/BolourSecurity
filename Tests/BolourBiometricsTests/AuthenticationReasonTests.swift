import Testing
@testable import BolourBiometrics

@Suite("AuthenticationReason construction")
struct AuthenticationReasonTests {

    @Test("a non-empty verbatim string is accepted")
    func nonEmptyAccepted() {
        let reason = AuthenticationReason(verbatim: "Unlock your vault")
        #expect(reason.resolvedString == "Unlock your vault")
    }

    @Test("distinct reasons compare unequal, matching reasons compare equal")
    func equality() {
        #expect(AuthenticationReason(verbatim: "Unlock") == AuthenticationReason(verbatim: "Unlock"))
        #expect(AuthenticationReason(verbatim: "Unlock") != AuthenticationReason(verbatim: "Confirm"))
    }

    // `verbatim:` enforces non-emptiness via `precondition`, so the empty-string rejection itself
    // can't be asserted without crashing the whole test run (Swift Testing has no "expect trap"
    // primitive on this platform). What's tested here is the decision the precondition is built
    // on, which is where the actual logic — and any future regression — would live.
    @Test("the validity check the precondition is built on rejects only the empty string")
    func validityCheck() {
        #expect(!AuthenticationReason.isValid(""))
        #expect(AuthenticationReason.isValid("x"))
        #expect(AuthenticationReason.isValid("Unlock your vault"))
    }
}
