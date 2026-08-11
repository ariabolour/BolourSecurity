# BlurKeychain

**Layer 1 · Primitives.** The keychain as it should have been.

## Mission

Replace the `SecItemAdd`/`CFDictionary`/`OSStatus` experience with a typed, async, value-semantic API in which every stored item's protection, sync, and presence requirements are explicit, defaulted to the strongest setting, and readable at the call site. Storing a secret correctly should take one line; storing one incorrectly should take deliberate effort.

## Responsibilities

- Generic-password keychain items: store, load, update, remove, enumerate.
- Typed protection semantics (`ProtectionPolicy`), sync semantics (`Synchronizability`), and user-presence gating (`PresenceRequirement`) via `SecAccessControl`.
- Access groups and app-group sharing, explicitly.
- Codable convenience for structured secrets via `SecretConvertible`.
- The `SecretStore` conformance other modules consume through the Core seam.
- Translating every `OSStatus` into a `KeychainError` case that teaches.

Out of scope: certificates/identities (BlurCertificates at v2.x), internet passwords with autofill semantics (roadmap), encrypted blobs above item size norms (BlurSecureStorage's job).

## Public API (signature-level design)

```swift
public struct Keychain: Sendable {
    /// `service` defaults to the main bundle identifier.
    public init(
        service: String? = nil,
        accessGroup: AccessGroup? = nil,
        protection: ProtectionPolicy = .default,        // whenUnlocked, thisDeviceOnly
        logger: (any SecurityEventLogger)? = nil
    )

    // MARK: Secrets (SecureBytes is the native currency)
    public func store(_ secret: SecureBytes, for key: ItemKey,
                      presence: PresenceRequirement = .none) async throws(KeychainError)
    public func secret(for key: ItemKey,
                       context: AuthenticatedContext? = nil) async throws(KeychainError) -> SecureBytes?
    public func removeSecret(for key: ItemKey) async throws(KeychainError)

    // MARK: Typed values (any SecretConvertible; Codable adapter provided)
    public func store<Value: SecretConvertible>(_ value: Value, for key: ItemKey,
                      presence: PresenceRequirement = .none) async throws(KeychainError)
    public func value<Value: SecretConvertible>(_ type: Value.Type = Value.self,
                      for key: ItemKey,
                      context: AuthenticatedContext? = nil) async throws(KeychainError) -> Value?

    // MARK: Introspection & maintenance
    public func contains(_ key: ItemKey) async throws(KeychainError) -> Bool
    public func allKeys() async throws(KeychainError) -> [ItemKey]
    /// Removes every item in this Keychain's service + access group. Named to read destructive.
    public func removeAllSecrets() async throws(KeychainError)
}

public struct AccessGroup: Sendable, Hashable, ExpressibleByStringLiteral {
    public static func appGroup(_ identifier: String) -> AccessGroup
    public static func team(_ identifier: String) -> AccessGroup
}

public enum KeychainError: SecurityError {
    case itemNotFound(ItemKey)                       // distinct from returning nil: see note
    case duplicateItem(ItemKey)
    case authenticationRequired(ItemKey)             // presence-gated item, no valid context
    case authenticationFailed(underlying: OSStatus)
    case interactionNotAllowed                       // locked device + whenUnlocked item: teaches the fix
    case protectionUnsatisfiable(ProtectionPolicy)   // e.g. whenPasscodeSet with no passcode
    case accessGroupDenied(AccessGroup)              // entitlement mismatch: the #1 support question, pre-answered
    case unexpectedItemShape
    case underlying(OSStatus)                        // always last-resort, never swallowed
}
// Reads return nil for "absent" (a normal state); `itemNotFound` is thrown only by
// operations that *require* existence (update/remove of a named item).

// MARK: Property-wrapper sugar (convenience tier, not the core API)
@propertyWrapper
public struct KeychainStored<Value: SecretConvertible & Sendable> {
    /// Synchronous access backed by SecItem's synchronous engine; documented as
    /// unsuitable for presence-gated items (those must use the async API).
    public init(_ key: ItemKey, keychain: Keychain = Keychain())
    public var wrappedValue: Value? { get nonmutating set }
    public var projectedValue: Keychain { get }
}
```

## Dependencies

`BlurSecurityCore`; Apple: Security (Keychain Services), LocalAuthentication (context pass-through only), Foundation.

## Architecture

- One internal `ItemDescriptor` type owns the *entire* mapping to `kSec*` dictionaries; no `CFDictionary` construction anywhere else. The mapping table is exhaustively unit-tested, including the `ProtectionPolicy` × `Synchronizability` × `PresenceRequirement` matrix and its OS-imposed invalid corners (which are unrepresentable in our types — e.g. `.whenPasscodeSet` has no sync spelling).
- Async surface over Keychain Services' synchronous engine: calls hop to a cooperative-pool executor so the main actor never blocks on keychain I/O (iCloud-synchronized items can be slow).
- `PresenceRequirement != .none` builds a `SecAccessControl`; reads of gated items accept an `AuthenticatedContext` (BlurBiometrics' LAContext wrapper, passed through a Core seam) to reuse a fresh authentication instead of double-prompting.
- `Keychain` is a configuration value — copying it is meaningless and safe; two equal configurations address the same items. This is why there is no singleton: identity lives in the OS, not the wrapper.

## Usage Examples

```swift
import BlurKeychain

extension ItemKey { static let refreshToken: ItemKey = "auth.refresh-token" }

// The five-minute win: one secure line each way
let keychain = Keychain()
try await keychain.store(tokenBytes, for: .refreshToken)
let token = try await keychain.secret(for: .refreshToken)

// Biometry-gated credential, shared with a widget via app group
let vaultChain = Keychain(accessGroup: .appGroup("group.com.example.shared"))
try await vaultChain.store(masterSecret, for: .vaultMaster, presence: .biometry())
```

## Testing Strategy

- **Descriptor mapping tests** (pure, exhaustive): every policy combination → expected `kSec*` dictionary, snapshot-verified.
- **Integration tests against the real keychain** on simulator/device CI: round-trips, update semantics, `allKeys` isolation between services, access-group behavior (device CI with entitlements), error mapping for forced `OSStatus` failures.
- Presence-gated paths are device-CI-tagged (`.requiresDevice`, `.requiresBiometryEnrollment`); simulator runs assert the correct `authenticationRequired` throw.
- Concurrency tests: parallel store/read/remove storms on one key — last-writer-wins with no torn reads, no `errSecDuplicateItem` leaks to callers (internal add-then-update handling).
- `@KeychainStored` semantics tests, including its documented refusal (typed throw at init) of presence-gated keys.

## Security Considerations & Common Mistakes Prevented

- **Prevented: accidental iCloud sync of device credentials** — sync is opt-in per Keychain instance, visible at the call site.
- **Prevented: over-available items** — the raw SDK default (`kSecAttrAccessibleWhenUnlocked` *without* this-device-only) is weaker than ours; developers who configure nothing get device-only.
- **Prevented: entitlement-mismatch mystery failures** — `accessGroupDenied` names the group and its `errorDescription` explains the entitlement fix, converting the keychain's most notorious `-34018`-class debugging session into a read.
- **Prevented: stale-biometry access** — presence defaults to `.biometry(.currentSet)` semantics when biometry is chosen (Core default).
- **Honest limits:** keychain items survive app uninstall on iOS (documented prominently — apps must decide first-run policy; the docs article shows the recommended `removeAllSecrets()`-on-fresh-install pattern). Keychain data is per-device-class protected by the OS; we do not add redundant app-layer encryption here — that's `BlurSecureStorage`'s layer.

## Future Roadmap

- Internet-password items with associated-domain awareness (v0.5).
- Shared-web-credential / passkey adjacency review with AuthenticationServices (v2.x, own ADR).
- Keychain item migration helper (`migrate(from: legacyQuery)`) for apps replacing hand-rolled keychain code (v1.0 — adoption-critical).
- watchOS-optimized slim path audit (v0.5).
