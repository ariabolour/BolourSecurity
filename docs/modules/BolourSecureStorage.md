# BolourSecureStorage

**Layer 2 · Capabilities.** Encrypted vaults for data too big for the keychain; a token store for the secrets apps actually manage.

## Mission

Answer the two storage questions every serious app eventually asks — *"where do I put encrypted files/documents?"* and *"where do my tokens live?"* — with one module: `Vault`, an encrypted file container layered on Data Protection **plus** app-layer AES-GCM; and `TokenStore`, a typed credential store with expiry semantics, built on `BolourKeychain`. This is defense in depth as a default, not a whitepaper diagram.

> **Current implementation status:** the vault master key is software-held in the keychain today, **not** Secure-Enclave-wrapped — see [Honest Limits](#security-considerations--common-mistakes-prevented) below and [CHANGELOG's Known limitations](../../CHANGELOG.md#known-limitations). SE-wrapping is the intended design ([ADR-0006](../adr/0006-secure-enclave-first-key-design.md)) and tracked as future work, not a shipped guarantee — the module's own `Vault.swift` doc comment has always said so; this page previously didn't match it, which is a documentation bug in itself for a security-sensitive claim.

## Responsibilities

- `Vault`: named, encrypted file containers — write/read/enumerate/delete by path, streaming support for large payloads.
- Key hierarchy management: per-file data keys, derived via HKDF from a per-vault master key held as a keychain item — invisible to the caller, documented for the auditor. Secure Enclave wrapping of the master key is the target design ([ADR-0006](../adr/0006-secure-enclave-first-key-design.md)) but is **not yet implemented**; see the status note above.
- `TokenStore`: typed storage for tokens/credentials with issuance/expiry metadata; the canonical `SecretStore` conformer that `BolourOAuth` consumes through the Core seam.
- File-protection class application (`ProtectionPolicy` → `FileProtectionType`) on every artifact it writes.

Out of scope: sync (vaults are device-bound by mission), database encryption (documented pattern: keep the *key* here, bring your own store), small ad-hoc secrets (that's `BolourKeychain` directly).

## Public API (signature-level design)

```swift
// MARK: Vault
public actor Vault {
    /// Opens (creating if needed) a named vault under Application Support.
    /// presence != .none gates every open with biometry/passcode via the master key.
    public static func open(
        named name: VaultName,
        protection: ProtectionPolicy = .default,
        presence: PresenceRequirement = .none,
        context: AuthenticatedContext? = nil
    ) async throws(StorageError) -> Vault

    public func write(_ data: Data, to path: VaultPath) async throws(StorageError)
    public func read(from path: VaultPath) async throws(StorageError) -> Data
    public func contents(of directory: VaultPath = .root) async throws(StorageError) -> [VaultPath]
    public func remove(_ path: VaultPath) async throws(StorageError)

    /// Streaming for payloads that shouldn't exist in memory at once.
    public func writeStream(to path: VaultPath) async throws(StorageError) -> VaultWriteStream
    public func readStream(from path: VaultPath) async throws(StorageError) -> VaultReadStream

    /// Destroys the vault AND its master key. Irreversible; named accordingly.
    public func destroyVaultAndAllContents() async throws(StorageError)
}

public struct VaultName: Sendable, Hashable, ExpressibleByStringLiteral { … }
public struct VaultPath: Sendable, Hashable, ExpressibleByStringLiteral {
    public static var root: VaultPath { get }
    // Normalized + validated at init: traversal ("..", absolute paths) unrepresentable.
}

// MARK: Token store
public struct TokenStore: SecretStore, Sendable {
    public init(keychain: Keychain = Keychain(),
                namespace: ItemKey = "bolour.tokens")

    public func store(_ token: StoredToken, for key: ItemKey) async throws(StorageError)
    /// Returns nil for absent OR expired-and-pruned tokens — callers see one "get a
    /// valid token or refresh" decision point, not two.
    public func validToken(for key: ItemKey,
                           leeway: Duration = .seconds(30)) async throws(StorageError) -> StoredToken?
    public func removeToken(for key: ItemKey) async throws(StorageError)
}

public struct StoredToken: Sendable, SecretConvertible {
    public init(value: SecureBytes, issuedAt: Date = .now, expiresAt: Date?)
    public var value: SecureBytes { get }
    public var expiresAt: Date? { get }
    public var isExpired: Bool { get }
}

public enum StorageError: SecurityError {
    case vaultLocked(VaultName)                    // presence-gated, no valid context
    case pathNotFound(VaultPath)
    case integrityCheckFailed(VaultPath)           // tamper or corruption: fails closed, teaches triage
    case masterKeyUnavailable(reason: MasterKeyUnavailabilityReason)  // corrupt key, or presence required
    case storageExhausted
    case underlying(any Error & Sendable)
}
```

## Dependencies

`BolourSecurityCore`, `BolourKeychain`, `BolourCrypto`; Apple: Foundation (FileManager, Data Protection attributes).

## Architecture

- **Key hierarchy:** each file gets a fresh data key (AES-256-GCM via `BolourCrypto.SymmetricKey`), derived via HKDF from the vault master key; the master key itself is held as a keychain item (via `BolourKeychain`) protected by the vault's `ProtectionPolicy`/`PresenceRequirement`. **It is software-held today, not Secure Enclave-wrapped** — that is ADR-0006's stated direction for this module, not its current state (see the status note at the top of this document). There is no master-key rotation API today — see Testing Strategy and Future Roadmap below.
- **On-disk format:** versioned envelope per file — header (format version, wrapped data key, nonce material handled inside `SealedMessage`) + sealed body; file names within the vault are themselves encrypted (directory-listing metadata privacy), with the `VaultPath` index kept in a sealed manifest.
- `Vault` is one of the three sanctioned actors ([Architecture.md §6](../Architecture.md)): it serializes manifest mutations and file handles; reads of distinct files proceed concurrently via internal task groups.
- Every artifact written also carries the mapped `FileProtectionType` — app-layer crypto is *in addition to* Data Protection, never a substitute (defense in depth is the module's reason to exist).
- Crash safety: manifest updates are write-to-temp + atomic-replace; a crash mid-write can lose the newest file, never corrupt the vault (tested).

## Usage Examples

```swift
import BolourSecureStorage

// A biometry-gated document vault in two lines
let vault = try await Vault.open(named: "HealthRecords", presence: .biometry())
try await vault.write(reportPDF, to: "reports/2026-08.pdf")

// Token storage with expiry pruning built in
let tokens = TokenStore()
try await tokens.store(StoredToken(value: accessBytes, expiresAt: expiry), for: .accessToken)
if let token = try await tokens.validToken(for: .accessToken) { … } else { /* refresh */ }
```

## Testing Strategy

- Round-trip suites (empty payloads through chunked streaming) and a concurrent-writes-to-distinct-paths storm asserting actor serialization leaves every write intact.
- **Tamper detection:** a bit-flip anywhere in a file's sealed body, or anywhere in the sealed manifest, is detected and throws `integrityCheckFailed` — never returns garbage plaintext. A truncated on-disk file fails closed without affecting other entries (the crash-safety proxy: no kill-injection harness exists yet, this is the coverage that stands in for it today).
- **Not yet implemented, so not yet tested:** master-key rotation (there is no `rotate`-style API on `Vault` at all today) and SE-key-invalidation recovery (`MasterKeyUnavailabilityReason` has exactly two cases, `.corruptStoredKey` and `.presenceRequired` — no SE-specific case exists, because there's no SE-backed key yet). Both were previously implied here as if already covered; they're recorded as roadmap items instead — see the module's Future Roadmap and the status note at the top of this document.
- `TokenStore`: expiry/leeway boundary tests; conformance suite run against the `SecretStore` protocol (shared with any future conformer).

## Security Considerations & Common Mistakes Prevented

- **Prevented: "I encrypted it and put it in Documents" with a key in UserDefaults** — the classic. The key hierarchy, keychain custody, and file protection come as one unit; there is no API to obtain a vault's master key.
- **Prevented: unauthenticated or nonce-reusing file crypto** — inherited by construction from `BolourCrypto`.
- **Prevented: path traversal** — `VaultPath` normalizes and rejects at init.
- **Prevented: metadata leakage via file names** — encrypted names + sealed manifest.
- **Prevented: tokens without expiry discipline** — `StoredToken` makes expiry a constructor decision; `validToken` makes staleness one branch.
- **Honest limits:** vault contents are excluded from encrypted-name search (documented); iCloud/device backups include vault files but not the device-only keychain-held master key (this holds regardless of whether the key is software- or SE-backed — it's a property of `.thisDeviceOnly`-class Keychain accessibility, not of SE specifically), so restored-to-new-device vaults are unreadable by design — the docs make this loud, because it is simultaneously the security property and the support ticket.

## Future Roadmap

- **Secure Enclave-wrapped master key** — the ADR-0006 commitment this module doesn't yet deliver on; the actual gap between design intent and shipped code (see the status note at the top of this document).
- **Master-key rotation API** — no `rotate`-style method exists on `Vault` today.
- Master-key escrow/recovery-code option for backup-restorable vaults (v2.0 — explicit, name-carries-the-tradeoff API, own ADR).
- Multi-recipient sealed sharing built on BolourCrypto envelope helpers (v2.x).
- SQLite-adjacent guidance article + `DatabaseKeyProvider` seam for SQLCipher-style integrations without taking the dependency (v1.x).
- Vault compaction and secure-delete best-effort documentation (APFS realities honestly stated) (v0.5).
