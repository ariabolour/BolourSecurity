import Testing
import Foundation
import BlurKeychain
import BlurSecurityCore

@Suite("KeychainError")
struct KeychainErrorTests {

    @Test("every case has a teaching description and recoverability verdict")
    func messagesExist() {
        let cases: [KeychainError] = [
            .itemNotFound("k"), .duplicateItem("k"), .authenticationRequired("k"),
            .authenticationFailed(underlying: -25293), .interactionNotAllowed,
            .protectionUnsatisfiable(.whenPasscodeSet), .accessGroupDenied("group.example"),
            .unexpectedItemShape, .underlying(-34018),
        ]
        for error in cases {
            #expect(error.errorDescription?.isEmpty == false)
            // failureIsRecoverable is a total function — just exercise it.
            _ = error.failureIsRecoverable
        }
    }

    @Test("recoverable vs terminal cases are classified")
    func recoverability() {
        #expect(KeychainError.interactionNotAllowed.failureIsRecoverable)
        #expect(KeychainError.authenticationFailed(underlying: -25293).failureIsRecoverable)
        #expect(KeychainError.itemNotFound("k").failureIsRecoverable == false)
        #expect(KeychainError.protectionUnsatisfiable(.default).failureIsRecoverable == false)
    }

    @Test("access-group denial names the group and the entitlement fix")
    func accessGroupDeniedTeaches() {
        let error = KeychainError.accessGroupDenied("group.com.example.shared")
        #expect(error.errorDescription?.contains("group.com.example.shared") == true)
        #expect(error.recoverySuggestion?.contains("entitlement") == true)
    }
}
