import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink("Keychain", destination: KeychainValidationView())
                    NavigationLink("Secure Enclave", destination: SecureEnclaveValidationView())
                    NavigationLink("Biometrics", destination: BiometricValidationView())
                    NavigationLink("App Attest", destination: AppAttestValidationView())
                    NavigationLink("OAuth Sign-In", destination: OAuthValidationView())
                } header: {
                    Text("Validation Surfaces")
                } footer: {
                    Text("Each screen exercises a real BolourSecurity API against this device or simulator and reports the actual result — success, a typed error, or an honest \"unsupported\" — never a scripted double. See docs/IntegrationTesting.md in the main repo for what's automated today versus what only this app or a physical device can exercise.")
                }
            }
            .navigationTitle("BolourSecurity")
        }
    }
}

#Preview {
    ContentView()
}
