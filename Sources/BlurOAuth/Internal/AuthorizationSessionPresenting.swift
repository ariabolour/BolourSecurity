import Foundation
import AuthenticationServices

/// An internal seam around `ASWebAuthenticationSession`, so the authorization leg — everything
/// up to getting a redirect URL back — is scripted in unit tests. A UI-test lane on device CI
/// exercises the real web session against a harness separately.
protocol AuthorizationSessionPresenting: Sendable {
    func present(
        url: URL, callbackURLScheme: String, prefersEphemeralSession: Bool, anchor: ASPresentationAnchor
    ) async throws(OAuthError) -> URL
}
