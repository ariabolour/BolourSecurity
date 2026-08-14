import BlurSecurityCore

/// A presence token produced by a successful ``BiometricAuthenticator/authenticate(reason:policy:reuseWindow:)``.
///
/// Wraps the `LAContext` used to satisfy the policy — the concrete conformer of Core's
/// ``PresenceAuthenticated`` seam — so a caller can perform one authentication and reuse it
/// across `BlurKeychain`/`BlurCrypto` operations rather than triggering a second biometric
/// prompt per call. Deliberately short-lived: nothing renews it, and ``invalidate()`` lets a
/// caller end it early (e.g. once its logical operation completes).
public struct AuthenticatedContext: Sendable, PresenceAuthenticated {
    public let authenticatedAt: ContinuousClock.Instant
    public let method: AuthenticationMethod
    private let evaluator: any PolicyEvaluating

    init(method: AuthenticationMethod, evaluator: any PolicyEvaluating, authenticatedAt: ContinuousClock.Instant) {
        self.method = method
        self.evaluator = evaluator
        self.authenticatedAt = authenticatedAt
    }

    public var authenticationContext: AnyObject? { evaluator.platformContext }

    /// Ends the session early. `BlurKeychain`/`BlurCrypto` calls made with this context after
    /// invalidation fail the same way they would after the OS invalidates it on its own.
    public func invalidate() {
        evaluator.invalidateContext()
    }
}
