import SwiftUI
import BolourSecurity

struct BiometricValidationView: View {
    @StateObject private var log = ActionLog()
    @State private var availability: BiometryAvailability?
    private let authenticator = BiometricAuthenticator()

    var body: some View {
        List {
            Section("BolourBiometrics") {
                Text("Reads live biometric availability and, on \"Authenticate\", runs a real system prompt. In Simulator: Features > Face ID/Touch ID > Enrolled, then Matching/Non-matching Face to drive the prompt.")
                    .font(.footnote).foregroundStyle(.secondary)
                if let availability {
                    Text("Availability: \(String(describing: availability))")
                        .font(.system(.footnote, design: .monospaced))
                }
            }
            Section("Actions") {
                Button("Refresh availability") { refreshAvailability() }
                Button("Authenticate") { log.run("authenticate") { try await authenticate() } }
            }
            ActionLogView(log: log)
        }
        .navigationTitle("Biometrics")
        .onAppear { refreshAvailability() }
    }

    private func refreshAvailability() {
        availability = authenticator.availability()
    }

    private func authenticate() async throws -> String {
        let context = try await authenticator.authenticate(
            reason: AuthenticationReason(verbatim: "Validate BolourBiometrics in the integration app")
        )
        return "authenticated via \(String(describing: context.method))"
    }
}

#Preview {
    NavigationStack { BiometricValidationView() }
}
