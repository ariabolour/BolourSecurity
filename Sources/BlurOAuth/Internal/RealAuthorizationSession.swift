import Foundation
import AuthenticationServices

/// The real `AuthorizationSessionPresenting` conformer: a thin async bridge over
/// `ASWebAuthenticationSession`'s completion-handler API, matching the bridge pattern already
/// used for `LAContext`/`DCAppAttestService`.
final class RealAuthorizationSession: NSObject, AuthorizationSessionPresenting, @unchecked Sendable {
    private let lock = NSLock()
    private var activeSession: ASWebAuthenticationSession?
    private var activeContextProvider: ContextProvider?

    /// Holds the caller-supplied anchor; a plain object rather than `self` conforming directly,
    /// so a fresh, disposable provider exists per attempt.
    private final class ContextProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
        let anchor: ASPresentationAnchor
        nonisolated init(anchor: ASPresentationAnchor) { self.anchor = anchor }
        func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { anchor }
    }

    func present(
        url: URL, callbackURLScheme: String, prefersEphemeralSession: Bool, anchor: ASPresentationAnchor
    ) async throws(OAuthError) -> URL {
        do {
            return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
                let provider = ContextProvider(anchor: anchor)
                let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackURLScheme) { [weak self] callbackURL, error in
                    self?.clearActiveSession()
                    if let callbackURL {
                        continuation.resume(returning: callbackURL)
                    } else {
                        continuation.resume(throwing: error ?? URLError(.unknown))
                    }
                }
                session.presentationContextProvider = provider
                session.prefersEphemeralWebBrowserSession = prefersEphemeralSession

                lock.lock()
                activeSession = session
                activeContextProvider = provider
                lock.unlock()

                session.start()
            }
        } catch let error as ASWebAuthenticationSessionError where error.code == .canceledLogin {
            throw OAuthError.userCancelledSignIn
        } catch {
            throw OAuthError.codeExchangeFailed(statusCode: nil, providerError: nil)
        }
    }

    private func clearActiveSession() {
        lock.lock(); activeSession = nil; activeContextProvider = nil; lock.unlock()
    }
}
