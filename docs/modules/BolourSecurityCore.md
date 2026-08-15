# BolourSecurityCore

**Layer 0 · Foundation.** The shared security vocabulary of the ecosystem.

## Mission

Define the small set of types, protocols, and guarantees that every other BolourSecurity module speaks — so that a protection policy means the same thing in `BolourKeychain` and `BolourSecureStorage`, an error behaves the same way in every `catch`, and a secret is never printable anywhere.

## Responsibilities

- The `SecurityError` protocol and error-design contract ([ADR-0004](../adr/0004-typed-throws-error-architecture.md)).
- Protection vocabulary: `ProtectionPolicy`, `Synchronizability`, `PresenceRequirement`.
- `SecureBytes`: the ecosystem's secret-bearing buffer.
- Protocol seams that decouple layers: `SecretStore`, `TrustEvaluating`, `AttestationProviding`.
- `SecurityEventLogger`: redaction-guaranteed audit logging.
- Nothing else. Core has no features — it has vocabulary. Anything with behavior belongs in a capability module (there is deliberately no `BolourUtilities`; see [ADR-0005](../adr/0005-consolidated-module-set.md)).

## Public API (signature-level design)

```swift
// MARK: Errors
public protocol SecurityError: Error, LocalizedError,
                               CustomDebugStringConvertible, Sendable {
    /// Whether retrying or user action can plausibly succeed.
    var failureIsRecoverable: Bool { get }
}
// Contract (enforced in review + tests): no conforming type ever carries
// key material, plaintext, tokens, or credentials in any description.

// MARK: Protection vocabulary
public enum ProtectionPolicy: Sendable, Hashable {
    /// Accessible only while the device is unlocked. The ecosystem default.
    case whenUnlocked(Synchronizability = .thisDeviceOnly)
    /// Accessible after first unlock since boot (background refresh use cases).
    case afterFirstUnlock(Synchronizability = .thisDeviceOnly)
    /// Exists only while a passcode is set; removed if passcode is removed.
    /// This-device-only by OS design — no sync parameter exists to misuse.
    case whenPasscodeSet

    public static var `default`: ProtectionPolicy { .whenUnlocked() }
}

public enum Synchronizability: Sendable, Hashable {
    case thisDeviceOnly          // default everywhere
    case synchronizable          // iCloud Keychain; explicit opt-in
}

public enum PresenceRequirement: Sendable, Hashable {
    case none
    /// Any user presence: biometry or device passcode.
    case userPresence
    /// Biometry only. `.currentSet` (default) invalidates on re-enrollment.
    case biometry(BiometrySet = .currentSet)
    case devicePasscode

    public enum BiometrySet: Sendable, Hashable {
        case currentSet          // safe default: fingerprints/faces added later don't qualify
        case anyEnrolled         // explicit, weaker
    }
}

// MARK: Secret memory
public struct SecureBytes: Sendable, Hashable, ContiguousBytes {
    public init(_ bytes: some Sequence<UInt8>)
    public init(count: Int)                          // zero-filled
    public var count: Int { get }
    public var isEmpty: Bool { get }
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    // Storage is zeroed on deinit (best-effort; see Security Considerations).
    // description / debugDescription: "SecureBytes(<count> bytes, redacted)"
    // NOT Codable. Explicit lossy exit only:
    public func dangerouslyExportBytes() -> Data     // name is the warning
}

/// Conformance for app types that can be stored as secrets (tokens, credentials).
public protocol SecretConvertible: Sendable {
    init(secureBytes: SecureBytes) throws
    func secureBytesRepresentation() throws -> SecureBytes
}

// MARK: Seams (concrete conformers live in higher modules)
public protocol SecretStore: Sendable {
    func store(_ secret: SecureBytes, for key: ItemKey) async throws
    func secret(for key: ItemKey) async throws -> SecureBytes?
    func removeSecret(for key: ItemKey) async throws
}

public struct ItemKey: Sendable, Hashable, ExpressibleByStringLiteral {
    public init(_ rawValue: String)
    public var rawValue: String { get }
    // Apps extend with static members: extension ItemKey { static let refreshToken: ItemKey }
}

public protocol TrustEvaluating: Sendable {
    // Conformed to by BolourCertificates.TrustEvaluator; consumed by BolourNetworkSecurity.
}

public protocol AttestationProviding: Sendable {
    // Conformed to by BolourAppIntegrity.AttestationService; consumed by apps' networking layers.
}

// MARK: Logging
public protocol SecurityEventLogger: Sendable {
    func log(_ event: SecurityEvent)
}
public struct SecurityEvent: Sendable {
    // Closed set of structured, pre-redacted events (itemStored, authenticationSucceeded,
    // pinningFailure(host:), …). Free-form string payloads are deliberately absent:
    // if you can't put a String in, you can't leak a secret through the logger.
}
public struct OSLogSecurityEventLogger: SecurityEventLogger { … }   // os.log-backed default
```

## Dependencies

Foundation, `os`. Nothing else — Core is the bottom of the graph and imports no BolourSecurity module.

## Architecture

Core is ~15 public types and intentionally frozen-feeling. Every addition to Core taxes all ten modules above it, so the bar is: *at least two modules need it, and it carries no behavior beyond its own invariants.* `SecurityEvent` is a closed enum-like struct so the logger cannot become a secret-leaking channel. `ItemKey` is `ExpressibleByStringLiteral` for ergonomics but apps are steered (docs, examples) toward declared static members so key strings live in one reviewed place.

## Usage Example

```swift
import BolourSecurityCore

extension ItemKey {
    static let refreshToken: ItemKey = "auth.refresh-token"
}

let policy: ProtectionPolicy = .afterFirstUnlock()          // deliberate, visible relaxation
let presence: PresenceRequirement = .biometry()             // current-set biometry
```

## Testing Strategy

- Swift Testing suites for: `SecureBytes` zeroing (probe deallocated storage in a controlled allocator harness), redacted descriptions (assert no byte content in `String(describing:)`/`reflecting:`), `ProtectionPolicy` ↔ `kSecAttrAccessible*` mapping tables (exhaustive).
- Compile-time misuse tests: negative compilation cases (e.g. `SecureBytes` is not `Codable`, `.whenPasscodeSet` accepts no sync argument) via `-verify`-style test fixtures.
- Property test: `SecretConvertible` round-trip for reference conformances.

## Security Considerations & Common Mistakes Prevented

- **Honest zeroization.** Swift's ARC and copy-on-write mean guaranteed zeroing of every copy is impossible in pure Swift. `SecureBytes` zeroes its owned storage on deinit and avoids implicit copies internally, and its documentation says exactly this — we reduce the window; we do not claim to eliminate it. Claims we can't keep don't ship.
- **Prevented: secrets in logs.** Structured `SecurityEvent` + redacted descriptions make the "print the token to debug it, forget to remove it" incident a type error, not a code-review hope.
- **Prevented: accidental iCloud sync.** `Synchronizability.thisDeviceOnly` is the default in every construct that accepts it.
- **Prevented: stale-biometry authorization.** `BiometrySet.currentSet` default means a newly enrolled face/fingerprint cannot unlock existing items.

## Future Roadmap

- `SecurityEvent` streaming (`AsyncSequence`) for audit pipelines (v0.5).
- Duress/jailbreak-signal vocabulary — types only; detection heuristics remain app policy (v2.x, with a dedicated ADR).
- Freeze Core (`@frozen` where applicable) at 1.0.
