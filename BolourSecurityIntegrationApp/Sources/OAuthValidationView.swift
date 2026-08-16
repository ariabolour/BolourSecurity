import SwiftUI
import UIKit
import BolourSecurity

/// Placeholder OAuth demo credentials. Every field below is a stand-in — replace them with a
/// real OAuth client's values to exercise `OAuthClient.signIn` end-to-end. Left as placeholders,
/// this screen explains that rather than failing confusingly against a fake URL. If you do fill
/// these in, also register `redirectURI`'s scheme under `CFBundleURLTypes` in this target's
/// Info.plist (via `project.yml`) so the system web-auth session can redirect back into the app.
enum OAuthDemoConfiguration {
    static let clientID = "YOUR_CLIENT_ID"
    static let authorizationEndpoint = URL(string: "https://example.com/oauth/authorize")!
    static let tokenEndpoint = URL(string: "https://example.com/oauth/token")!
    static let redirectURI = URL(string: "boloursecurityintegrationapp://callback")!

    static var isConfigured: Bool {
        clientID != "YOUR_CLIENT_ID" && authorizationEndpoint.host != "example.com"
    }
}

struct OAuthValidationView: View {
    @StateObject private var log = ActionLog()

    var body: some View {
        List {
            Section("BolourOAuth") {
                Text("Authorization Code + PKCE via ASWebAuthenticationSession, ID-token verification when OIDC. Needs a real OAuth client — edit OAuthDemoConfiguration in this file with your own provider's values.")
                    .font(.footnote).foregroundStyle(.secondary)
                Text(OAuthDemoConfiguration.isConfigured
                     ? "Configured with a non-placeholder client."
                     : "Not configured — still placeholder values. Sign-in is disabled until OAuthDemoConfiguration is edited.")
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(OAuthDemoConfiguration.isConfigured ? .green : .orange)
            }
            Section("Actions") {
                Button("Sign in") {
                    log.run("signIn") { try await signIn() }
                }
                .disabled(!OAuthDemoConfiguration.isConfigured)
            }
            ActionLogView(log: log)
        }
        .navigationTitle("OAuth Sign-In")
    }

    @MainActor
    private func signIn() async throws -> String {
        guard let anchor = UIApplication.shared.currentKeyWindow else {
            return "no key window available to present from"
        }
        let configuration = try OAuthConfiguration(
            authorizationEndpoint: OAuthDemoConfiguration.authorizationEndpoint,
            tokenEndpoint: OAuthDemoConfiguration.tokenEndpoint,
            clientID: OAuthDemoConfiguration.clientID,
            redirectURI: OAuthDemoConfiguration.redirectURI,
            scopes: .openID
        )
        let client = OAuthClient(configuration: configuration, tokenStore: TokenStore())
        let session = try await client.signIn(presentingFrom: anchor)
        let header = try await session.tokens.validAccessToken().headerValue
        return "signed in, access token header: \(header)"
    }
}

private extension UIApplication {
    var currentKeyWindow: UIWindow? {
        connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
    }
}

#Preview {
    NavigationStack { OAuthValidationView() }
}
