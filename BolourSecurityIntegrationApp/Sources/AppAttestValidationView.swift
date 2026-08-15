import SwiftUI
import BolourSecurity

struct AppAttestValidationView: View {
    @StateObject private var log = ActionLog()
    @State private var support: AttestationSupport?
    private let service = AttestationService()

    var body: some View {
        List {
            Section("BolourAppIntegrity") {
                Text("App Attest only works on a real device with your own Team ID and the App Attest capability enabled on your App ID — see this app's README. In Simulator this honestly reports unsupported rather than faking success.")
                    .font(.footnote).foregroundStyle(.secondary)
                if let support {
                    Text("Support: \(String(describing: support))")
                        .font(.system(.footnote, design: .monospaced))
                }
            }
            Section("Actions") {
                Button("Check support") { checkSupport() }
                Button("Attest (needs real device + entitlement)") { log.run("attestKey") { try await attest() } }
            }
            Section("What this does and doesn't prove") {
                Text("A successful attestKey() call here only proves the client produced an attestation object — it does NOT prove the app is legitimate. That verification happens server-side, against Apple, using the attestation object this screen shows. See the client-vs-server table in docs/modules/BolourAppIntegrity.md in the main repo.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            ActionLogView(log: log)
        }
        .navigationTitle("App Attest")
        .onAppear { checkSupport() }
    }

    private func checkSupport() {
        support = service.support
    }

    private func attest() async throws -> String {
        let challenge = ServerChallenge(Data("demo-challenge-\(UUID().uuidString)".utf8))
        let attestation = try await service.attestKey(challenge: challenge)
        return "attested key \(attestation.keyID): \(attestation.attestationObject.count)-byte attestation object (send this to your server to verify)"
    }
}

#Preview {
    NavigationStack { AppAttestValidationView() }
}
