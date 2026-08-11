/// A seam for an authenticated user-presence context that lower-layer modules can *consume*
/// without importing upward.
///
/// `BlurBiometrics` (Layer 2) will provide the concrete conformer — an `LAContext` wrapper —
/// so a caller can perform one authentication and reuse it, rather than triggering a second
/// biometric prompt. `BlurKeychain` and `BlurCrypto` (Layer 1) accept `any PresenceAuthenticated`
/// to receive it through this seam.
///
/// The underlying platform context is vended type-erased so Core imports no LocalAuthentication;
/// consumers pass the object straight to the platform APIs that accept an `LAContext`
/// (`kSecUseAuthenticationContext`, `SecKey` operations, …).
public protocol PresenceAuthenticated: Sendable {
    /// The platform authentication object — an `LAContext` — or `nil` if no live context is
    /// available. Type-erased so Core need not depend on LocalAuthentication.
    var authenticationContext: AnyObject? { get }
}
