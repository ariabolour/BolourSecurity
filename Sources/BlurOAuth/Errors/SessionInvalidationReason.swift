/// Why `TokenManager` can no longer refresh — the app's "route to sign-in" signal.
public enum SessionInvalidationReason: Sendable, Hashable {
    /// The provider reported a retired/reused refresh token — a strong signal of token theft
    /// or a client bug, never treated as "just retry."
    case refreshTokenReuseDetected
    /// The provider rejected the refresh token outright (`invalid_grant` with no rotation context).
    case refreshTokenRevoked
    /// No refresh token is available at all (e.g. after `signOut()`).
    case noRefreshToken
}
