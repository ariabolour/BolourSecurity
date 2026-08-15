# ADR-0004: Typed throws with per-module error domains

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** founding maintainer
- **Security impact:** Low — but error handling quality affects how apps behave under attack

## Context

Security APIs have unusually consequential failure paths. The difference between "biometry locked out," "biometry not enrolled," and "user cancelled" determines whether an app should fall back to passcode, re-enroll, or silently retry — and getting it wrong either locks users out or opens fallback paths an attacker can steer into. Untyped `throws` forces `catch let error as? BiometricError` pattern-matching that developers routinely skip, collapsing all failures into one generic path.

Swift 6 ships typed throws (`throws(E)`), giving exhaustive `catch` over closed error domains.

## Decision

1. Core defines the protocol every error conforms to:

```swift
public protocol SecurityError: Error, LocalizedError,
                               CustomDebugStringConvertible, Sendable {
    /// Whether retrying or user action can plausibly succeed.
    var failureIsRecoverable: Bool { get }
}
```

2. Each module defines exactly one public error enum (`KeychainError`, `CryptoError`, `BiometricError`, `CertificateError`, `PinningError`, `StorageError`, `JWTError`, `IntegrityError`, `OAuthError`) conforming to `SecurityError`.
3. Every public function whose failures are a closed domain uses typed throws: `func secret(for key: ItemKey) async throws(KeychainError) -> SecureBytes?`. Functions genuinely composing multiple domains (rare; mostly Layer 4) either define a composed enum or use untyped `throws` with the domains documented — never `any Error` silently.
4. **Redaction is a conformance requirement:** no case's associated values, `errorDescription`, or `debugDescription` may carry key material, plaintext, tokens, or credentials. Underlying `OSStatus`/`LAError` codes are preserved as associated values for diagnostics.
5. Every case documents: what failed, most likely cause, recovery suggestion. Error text is reviewed API surface (see [DeveloperExperience.md](../DeveloperExperience.md)).

## Alternatives Considered

- **Untyped `throws` everywhere (pre-Swift-6 convention).** Familiar, but discoverable failure handling dies: autocomplete can't show what to catch, exhaustiveness is impossible, and the "one generic catch" anti-pattern wins. Rejected.
- **One giant `BolourSecurityError` enum.** Exhaustive but violates composability (importing `BolourKeychain` would surface OAuth cases) and turns every new case anywhere into ecosystem-wide noise. Rejected.
- **`Result`-returning APIs.** Composes poorly with `async` call sites and doubles the API shapes. Rejected; `Result` appears only where a value legitimately *stores* an outcome.

## Consequences

- Easier: exhaustive `catch` with compiler enforcement; per-module error docs; error handling code that reads like a security policy.
- Harder: adding an error case to a frozen enum is API-breaking — we mark error enums `@frozen` only at 1.0 after the domains have proven stable, and until then document them as non-frozen.
- Security: apps can implement precise, reviewable fallback logic; redaction-by-conformance prevents secrets in logs.

## Revisit When

Typed-throws ergonomics change materially in future Swift releases, or real-world composition pressure (Layer 4) shows per-module domains are too granular.
