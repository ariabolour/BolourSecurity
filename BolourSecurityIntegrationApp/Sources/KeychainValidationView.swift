import SwiftUI
import BolourSecurity

struct KeychainValidationView: View {
    @StateObject private var log = ActionLog()
    private let keychain = Keychain(service: "com.ariabolour.BolourSecurityIntegrationApp.demo")
    private let key: ItemKey = "integration-app.demo-secret"

    var body: some View {
        List {
            Section("BolourKeychain") {
                Text("Exercises Keychain.store/secret/removeSecret against the real Data Protection keychain on this device or simulator — device-only, unlocked-only, no iCloud sync, by default.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section("Actions") {
                Button("Store a test secret") { log.run("store") { try await store() } }
                Button("Read it back") { log.run("read") { try await read() } }
                Button("Delete it") { log.run("delete") { try await delete() } }
            }
            ActionLogView(log: log)
        }
        .navigationTitle("Keychain")
    }

    private func store() async throws -> String {
        let secret = SecureBytes(Array("integration-app-\(UUID().uuidString.prefix(8))".utf8))
        try await keychain.store(secret, for: key)
        return "stored \(secret.count) bytes under \"\(key.rawValue)\""
    }

    private func read() async throws -> String {
        guard let secret = try await keychain.secret(for: key) else {
            return "no secret stored yet"
        }
        return "read back \(secret)"
    }

    private func delete() async throws -> String {
        try await keychain.removeSecret(for: key)
        return "deleted"
    }
}

#Preview {
    NavigationStack { KeychainValidationView() }
}
