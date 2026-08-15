import Testing
@testable import BolourSecureStorage

@Suite("VaultPath validation")
struct VaultPathTests {

    @Test("valid runtime paths are accepted and normalized")
    func validPaths() throws {
        let path = try VaultPath(validating: "reports/2026-08.pdf")
        #expect(path.storageKey == "reports/2026-08.pdf")
    }

    @Test("a leading slash is rejected")
    func absoluteRejected() {
        #expect(throws: StorageError.self) {
            _ = try VaultPath(validating: "/etc/passwd")
        }
    }

    @Test("parent-directory traversal is rejected", arguments: [
        "../secret", "reports/../../etc", "a/../b",
    ])
    func traversalRejected(_ string: String) {
        #expect(throws: StorageError.self) {
            _ = try VaultPath(validating: string)
        }
    }

    @Test(".root has no components and stringifies to /")
    func rootIsEmpty() {
        #expect(VaultPath.root.components.isEmpty)
        #expect("\(VaultPath.root)" == "/")
    }

    @Test("equal logical paths compare equal regardless of how they were constructed")
    func equality() throws {
        let literal: VaultPath = "reports/2026.pdf"
        let validated = try VaultPath(validating: "reports/2026.pdf")
        #expect(literal == validated)
    }
}
