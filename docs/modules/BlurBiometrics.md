# BlurBiometrics

**Layer 2 · Capabilities.** Face ID, Touch ID, Optic ID, and passcode — as one coherent policy API.

## Mission

Turn LocalAuthentication's stateful, error-code-driven `LAContext` dance into a value-oriented API: describe *what assurance you need* as a policy, call one async method, and receive either a scoped `AuthenticatedContext` usable by Keychain and Secure Enclave operations, or a typed error that tells you exactly which fallback is appropriate. This module owns the *local* half of authentication; federated sign-in is `BlurOAuth` ([ADR-0005](../adr/0005-consolidated-module-set.md)).

## Responsibilities

- Biometric and passcode authentication with composable policies.
- Availability introspection (`what biometry exists, is it enrolled, is it locked out`) as a typed state, not three booleans and an inout `NSError`.
- Producing `AuthenticatedContext` — the ecosystem's presence token — consumed by `BlurKeychain` reads and `SecureEnclaveKey` operations so users authenticate once per logical operation, not once per API call.
- Typed, localizable prompt reasons.
- Detecting biometry *changes* (re-enrollment) as a first-class signal for invalidation policies.

## Public API (signature-level design)

```swift
public struct BiometricAuthenticator: Sendable {
    public init(logger: (any SecurityEventLogger)? = nil)

    /// Introspect without prompting.
    public func availability() -> BiometryAvailability

    /// Authenticate. May present system UI; the reason is mandatory and typed.
    public func authenticate(
        reason: AuthenticationReason,
        policy: AuthenticationPolicy = .biometry(fallback: .devicePasscode),
        reuseWindow: Duration = .seconds(0)          // 0 = fresh authentication required
    ) async throws(BiometricError) -> AuthenticatedContext
}

public enum AuthenticationPolicy: Sendable, Hashable {
    /// Biometry first, with an explicit statement of what happens when it can't proceed.
    case biometry(fallback: Fallback)
    case devicePasscodeOnly
    /// visionOS companion-device / Apple Watch approval where the OS offers it.
    case userPresence

    public enum Fallback: Sendable, Hashable {
        case devicePasscode      // recommended default: users are never stranded
        case none                // biometry-or-fail: high-assurance flows, explicit choice
    }
}

public struct AuthenticationReason: Sendable, Hashable {
    /// Localizable, non-empty by construction. "Because the API demanded a string"
    /// prompts ("test", "reason") become impossible to ship silently.
    public init(_ key: String.LocalizationValue, bundle: Bundle = .main)
    public init(verbatim: String)                    // named escape for dynamic text
}

/// Presence token. Wraps a fresh LAContext; consumed by Keychain reads and
/// SecureEnclaveKey operations via the Core seam. Deliberately short-lived.
public struct AuthenticatedContext: Sendable {
    public var authenticatedAt: ContinuousClock.Instant { get }
    public var method: AuthenticationMethod { get }   // .faceID, .touchID, .opticID, .passcode, .watch
    public func invalidate()
}

public enum BiometryAvailability: Sendable, Hashable {
    case available(BiometryKind)
    case notEnrolled(BiometryKind)                   // hardware exists, nothing enrolled
    case lockedOut(BiometryKind)                     // too many failures; passcode will unlock
    case passcodeOnly                                // no biometric hardware, passcode set
    case unavailable(reason: UnavailabilityReason)   // no passcode set, MDM-disabled, …
}
public enum BiometryKind: Sendable, Hashable { case faceID, touchID, opticID }

public enum BiometricError: SecurityError {
    case userCancelled                               // user's decision: never retry-loop this
    case userChoseFallback                           // asked for passcode; honor it
    case biometryLockedOut                           // recovery: authenticate with passcode
    case biometryNotEnrolled
    case passcodeNotSet
    case authenticationFailed                        // genuine mismatch after retries
    case systemCancelled                             // app backgrounded etc.; safe to retry once
    case notAvailable(UnavailabilityReason)
}

/// Re-enrollment signal for invalidation policies (backed by evaluatedPolicyDomainState).
public struct BiometryState: Sendable, Hashable {
    public static func current() -> BiometryState?
    // Persist it; compare later. Inequality ⇒ biometry set changed since capture.
}
```

## Dependencies

`BlurSecurityCore`; Apple: LocalAuthentication, Foundation.

## Architecture

- `LAContext` is created fresh per `authenticate` call and owned by the returned `AuthenticatedContext`; contexts are never implicitly reused across logical operations (`reuseWindow` makes reuse an explicit, bounded decision that maps to `touchIDAuthenticationAllowableReuseDuration`).
- `LAContext` is not `Sendable`; the wrapper isolates it behind an internal locked box (`@unchecked Sendable` with the documented justification required by [ADR-0003](../adr/0003-swift6-strict-concurrency.md)).
- `availability()` folds `canEvaluatePolicy`'s boolean + error + `biometryType` triple into one exhaustive enum, evaluated at call time (the OS can change state between calls; docs say "check late, not early").
- Every `LAError` code maps to exactly one `BiometricError` case; the mapping table is public documentation, because apps in regulated industries must justify fallback flows to auditors.

## Usage Examples

```swift
import BlurBiometrics

let authenticator = BiometricAuthenticator()

switch authenticator.availability() {
case .available(.faceID):  break                    // show Face ID affordance
case .notEnrolled:         showEnrollmentEducation()
default:                   hideBiometricUI()
}

do {
    let context = try await authenticator.authenticate(
        reason: AuthenticationReason("Unlock your vault")
    )
    let secret = try await keychain.secret(for: .vaultMaster, context: context)
} catch .userCancelled {
    // respect it — no re-prompt
} catch .biometryLockedOut {
    // steer to passcode path
}
```

## Testing Strategy

- `LAContext` sits behind an internal `PolicyEvaluating` protocol; unit tests inject scripted doubles to cover **every** `LAError` → `BiometricError` mapping and every `BiometryAvailability` fold — exhaustively, as table-driven Swift Testing parameterized tests.
- `AuthenticationReason` construction tests (empty verbatim strings are rejected at init).
- Device CI (tagged `.requiresDevice`): real Face ID/Touch ID happy path via simulator biometric injection where available; real `BiometryState` change detection on enrollment change is a documented manual QA checklist item (it cannot be automated honestly — we say so).
- Concurrency: `authenticate` called concurrently must serialize prompts, never interleave system UI.

## Security Considerations & Common Mistakes Prevented

- **Prevented: `Bool`-result authentication.** There is no `-> Bool`. Success yields a capability (`AuthenticatedContext`); failure throws. An inverted `if` cannot silently pass an auth gate, and downstream APIs *require* the context, so "checked biometrics, then read the secret without any linkage" — the classic bypassable pattern — doesn't arise.
- **Prevented: retry-looping user cancellation** — `userCancelled` is a distinct case whose docs and examples establish the contract.
- **Prevented: unlocalized junk prompts** — `AuthenticationReason` is localization-first by construction.
- **Prevented: stale-enrollment trust** — `.currentSet` semantics from Core plus `BiometryState` give apps an auditable invalidate-on-change story.
- **Honest limits:** biometrics gate *access on this device*; they are not proof of identity to a server (that's `BlurAppIntegrity` + `BlurOAuth` territory, and the docs draw this line in the security-considerations article). Apps must also handle the OS-level truth that a device passcode holder can enroll new biometry.

## Future Roadmap

- Companion-device (Apple Watch approval) policy surfacing on macOS (v0.5).
- SwiftUI convenience layer (`.biometricallyGated` view modifier) — separate discussion; UI adjacency is at tension with "no security UI" (needs its own ADR before any commitment).
- App-level duress patterns article (documentation, not API) (v1.x).
