import Foundation
import AuthenticationServices
@testable import BolourOAuth

/// A scripted `AuthorizationSessionPresenting` double — the authorization leg (everything up to
/// getting a redirect URL back) is driven through this rather than a real
/// `ASWebAuthenticationSession` / web view.
final class FakeAuthorizationSessionPresenting: AuthorizationSessionPresenting, @unchecked Sendable {
    // No internal locking: each test constructs its own instance and calls `present` at most
    // once, so there is no real concurrent access to guard against.
    /// When set, the redirect callback echoes this authorization URL's own `state` (and, when
    /// `succeeds` is true, a canned `code`) — mirroring a real provider that reflects back
    /// whatever `state` the client sent. Set `succeeds = false` to simulate user cancellation.
    var succeeds = true
    var providerErrorCode: String?
    /// When set, the callback echoes THIS state instead of the one actually presented —
    /// simulating a mismatched/forged state on the redirect.
    var stateOverride: String?
    /// When set, the fake acts as an OIDC provider that remembers the outgoing nonce and signs
    /// a matching ID token before the token endpoint ever sees the code — mirroring how a real
    /// IdP associates the nonce with the authorization code server-side.
    var idp: LocalIdP?
    var idTokenSubject = "user-1"
    private(set) var lastPresentedURL: URL?

    func present(
        url: URL, callbackURLScheme: String, prefersEphemeralSession: Bool, anchor: ASPresentationAnchor
    ) async throws(OAuthError) -> URL {
        lastPresentedURL = url

        guard succeeds else { throw OAuthError.userCancelledSignIn }

        let queryItems = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let presentedState = queryItems.first(where: { $0.name == "state" })?.value ?? ""
        let state = stateOverride ?? presentedState

        if let idp {
            let nonce = queryItems.first(where: { $0.name == "nonce" })?.value
            idp.pendingIDToken = try? await idp.idToken(subject: idTokenSubject, audience: queryItems.first(where: { $0.name == "client_id" })?.value ?? "", nonce: nonce)
        }

        var components = URLComponents(string: "\(callbackURLScheme)://callback")!
        if let providerErrorCode {
            components.queryItems = [
                URLQueryItem(name: "error", value: providerErrorCode),
                URLQueryItem(name: "state", value: state),
            ]
        } else {
            components.queryItems = [
                URLQueryItem(name: "code", value: "test-authorization-code"),
                URLQueryItem(name: "state", value: state),
            ]
        }
        return components.url!
    }
}
