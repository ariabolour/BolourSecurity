import SwiftUI
import BolourSecurity

struct SecureEnclaveValidationView: View {
    @StateObject private var log = ActionLog()
    @State private var currentKey: SecureEnclaveKey?
    private let tag = "com.ariabolour.BolourSecurityIntegrationApp.se-demo-key"

    var body: some View {
        List {
            Section("BolourCrypto.SecureEnclaveKey") {
                Text("Creates, signs with, verifies, and destroys a real Secure Enclave-backed P-256 key. On hardware without a Secure Enclave, \"Create\" reports CryptoError.secureEnclaveUnavailable honestly instead of silently falling back to a software key (ADR-0006).")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section("Actions") {
                Button("Create key") { log.run("create") { try await create() } }
                Button("Sign a test message") { log.run("sign + self-verify") { try await signAndVerify() } }
                Button("Load by tag") { log.run("load") { try await load() } }
                Button("Destroy key") { log.run("destroy") { try await destroy() } }
            }
            ActionLogView(log: log)
        }
        .navigationTitle("Secure Enclave")
    }

    private func create() async throws -> String {
        let key = try SecureEnclaveKey.create(tag: tag)
        currentKey = key
        return "created key under tag \"\(tag)\""
    }

    private func signAndVerify() async throws -> String {
        guard let key = currentKey else { return "create a key first" }
        let message = Data("integration-app test message".utf8)
        let signature = try key.signature(for: message)
        let verified = try key.verificationKey.isValidSignature(signature, for: message)
        return "signed (\(signature.rawRepresentation.count) bytes), self-verify = \(verified)"
    }

    private func load() async throws -> String {
        guard let loaded = try SecureEnclaveKey.load(tag: tag) else {
            return "no key stored under \"\(tag)\""
        }
        currentKey = loaded
        return "loaded key under tag \"\(tag)\""
    }

    private func destroy() async throws -> String {
        guard let key = currentKey else { return "no key to destroy" }
        try key.destroy()
        currentKey = nil
        return "destroyed"
    }
}

#Preview {
    NavigationStack { SecureEnclaveValidationView() }
}
