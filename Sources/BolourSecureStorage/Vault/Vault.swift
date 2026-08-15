import Foundation
import BolourSecurityCore
import BolourKeychain
import BolourCrypto

/// An encrypted, named file container layered on Data Protection **plus** app-layer AES-GCM —
/// defense in depth as a default, not a whitepaper diagram.
///
/// **Key hierarchy:** each file gets a fresh data key, derived via HKDF from the vault's master
/// key and a random per-file salt (`VaultManifest.Entry.keySalt`); the master key itself is held
/// in the keychain, protected by the vault's `ProtectionPolicy`/`PresenceRequirement`. Logical
/// paths never touch the filesystem directly — every file is named with a random identifier, and
/// the `VaultPath → identifier` mapping lives only in the sealed manifest, so directory listings
/// on disk reveal nothing.
///
/// - Note: **Honest limits (v0.5 scope).** The master key is software-held in the keychain, not
///   yet Secure-Enclave-wrapped (`BolourCrypto.SecureEnclaveKey` doesn't exist yet either — this
///   tracks that same deferral). `writeStream`/`readStream` buffer their full payload in memory
///   rather than encrypting/decrypting in constant-memory segments — correct today for
///   reasonably sized files, not yet suited to the multi-GB tier the module's design doc
///   describes; a segmented-AEAD streaming cipher is future work.
public actor Vault {
    private let name: VaultName
    private let directoryURL: URL
    private let filesURL: URL
    private let manifestURL: URL
    private let keychain: Keychain
    private let masterKeyItemKey: ItemKey
    private let fileProtection: FileProtectionType
    private let masterKeyBytes: SecureBytes
    private var manifest: VaultManifest

    private static let fileKeyInfo = Data("bolour.securestorage.file-key.v1".utf8)

    private init(
        name: VaultName, directoryURL: URL, filesURL: URL, manifestURL: URL,
        keychain: Keychain, masterKeyItemKey: ItemKey, fileProtection: FileProtectionType,
        masterKeyBytes: SecureBytes, manifest: VaultManifest
    ) {
        self.name = name
        self.directoryURL = directoryURL
        self.filesURL = filesURL
        self.manifestURL = manifestURL
        self.keychain = keychain
        self.masterKeyItemKey = masterKeyItemKey
        self.fileProtection = fileProtection
        self.masterKeyBytes = masterKeyBytes
        self.manifest = manifest
    }

    /// Opens (creating if needed) a named vault under Application Support.
    ///
    /// `presence != .none` gates the master key with biometry/passcode: opening without a valid
    /// `context` from `BolourBiometrics` throws ``StorageError/masterKeyUnavailable(reason:)``.
    public static func open(
        named name: VaultName,
        protection: ProtectionPolicy = .default,
        presence: PresenceRequirement = .none,
        context: (any PresenceAuthenticated)? = nil
    ) async throws(StorageError) -> Vault {
        if case .none = presence {} else if context == nil {
            throw StorageError.masterKeyUnavailable(reason: .presenceRequired)
        }

        let directoryURL = try Vault.directoryURL(for: name)
        let filesURL = directoryURL.appendingPathComponent("files", isDirectory: true)
        let manifestURL = directoryURL.appendingPathComponent("manifest.sealed", isDirectory: false)
        let fileProtection = protection.fileProtectionType
        try Vault.ensureDirectory(filesURL, protection: fileProtection)

        let keychain = Keychain(service: "BolourSecureStorage.vault", protection: protection)
        let masterKeyItemKey = ItemKey("bolour.securestorage.vault.\(name.rawValue).masterkey")
        let masterKeyBytes = try await Vault.loadOrCreateMasterKey(
            keychain: keychain, itemKey: masterKeyItemKey, presence: presence, context: context
        )

        let manifest = try Vault.loadOrCreateManifest(
            at: manifestURL, masterKeyBytes: masterKeyBytes, fileProtection: fileProtection
        )

        return Vault(
            name: name, directoryURL: directoryURL, filesURL: filesURL, manifestURL: manifestURL,
            keychain: keychain, masterKeyItemKey: masterKeyItemKey, fileProtection: fileProtection,
            masterKeyBytes: masterKeyBytes, manifest: manifest
        )
    }

    /// Test-only: opens a vault rooted at an arbitrary directory with directly-supplied master
    /// key material, bypassing the real keychain and the real Application Support location
    /// entirely. `Keychain` round-trips can't run in hostless `swift test` bundles on any
    /// platform (see `BolourKeychainTests`'s `KeychainProbe` gate); this is how the file
    /// format/crypto logic that makes up the bulk of `Vault` stays fully local-testable without
    /// depending on that gate.
    static func openForTesting(
        directoryURL: URL, masterKeyBytes: SecureBytes, protection: ProtectionPolicy = .default
    ) throws(StorageError) -> Vault {
        let filesURL = directoryURL.appendingPathComponent("files", isDirectory: true)
        let manifestURL = directoryURL.appendingPathComponent("manifest.sealed", isDirectory: false)
        let fileProtection = protection.fileProtectionType
        try Vault.ensureDirectory(filesURL, protection: fileProtection)
        let manifest = try Vault.loadOrCreateManifest(
            at: manifestURL, masterKeyBytes: masterKeyBytes, fileProtection: fileProtection
        )
        return Vault(
            name: "test-vault", directoryURL: directoryURL, filesURL: filesURL, manifestURL: manifestURL,
            keychain: Keychain(service: "BolourSecureStorageTests"), masterKeyItemKey: "test.masterkey",
            fileProtection: fileProtection, masterKeyBytes: masterKeyBytes, manifest: manifest
        )
    }

    // MARK: - Reads & writes

    public func write(_ data: Data, to path: VaultPath) async throws(StorageError) {
        let salt = SecureRandom.data(count: 16)
        let dataKey = try deriveFileKey(salt: salt)
        let sealed: SealedMessage
        do { sealed = try dataKey.seal(data) } catch { throw StorageError.underlying(error) }

        let onDiskName = UUID().uuidString
        let fileURL = filesURL.appendingPathComponent(onDiskName, isDirectory: false)
        do {
            try sealed.combinedRepresentation.write(to: fileURL, options: .atomic)
            try Vault.applyProtection(fileProtection, to: fileURL)
        } catch { throw StorageError.underlying(error) }

        let replaced = manifest.entries[path.storageKey]
        manifest.entries[path.storageKey] = VaultManifest.Entry(onDiskName: onDiskName, keySalt: salt)
        try persistManifest()

        if let replaced, replaced.onDiskName != onDiskName {
            try? FileManager.default.removeItem(at: filesURL.appendingPathComponent(replaced.onDiskName))
        }
    }

    public func read(from path: VaultPath) async throws(StorageError) -> Data {
        guard let entry = manifest.entries[path.storageKey] else {
            throw StorageError.pathNotFound(path)
        }
        let fileURL = filesURL.appendingPathComponent(entry.onDiskName, isDirectory: false)
        let raw: Data
        do { raw = try Data(contentsOf: fileURL) } catch { throw StorageError.pathNotFound(path) }

        let sealed: SealedMessage
        do { sealed = try SealedMessage(combinedRepresentation: raw) }
        catch { throw StorageError.integrityCheckFailed(path) }

        let dataKey = try deriveFileKey(salt: entry.keySalt)
        do { return try dataKey.open(sealed) }
        catch { throw StorageError.integrityCheckFailed(path) }
    }

    public func contents(of directory: VaultPath = .root) async throws(StorageError) -> [VaultPath] {
        manifest.entries.keys
            .map { VaultPath(storageKey: $0) }
            .filter { path in
                path.components.count == directory.components.count + 1
                    && Array(path.components.prefix(directory.components.count)) == directory.components
            }
            .sorted { $0.storageKey < $1.storageKey }
    }

    public func remove(_ path: VaultPath) async throws(StorageError) {
        guard let entry = manifest.entries.removeValue(forKey: path.storageKey) else {
            throw StorageError.pathNotFound(path)
        }
        try persistManifest()
        try? FileManager.default.removeItem(at: filesURL.appendingPathComponent(entry.onDiskName))
    }

    // MARK: - Streaming

    /// Streaming for payloads that shouldn't exist in memory at once.
    ///
    /// - Note: v0.5 buffers the full payload in memory until `finish()` — see the "Honest
    ///   limits" note on ``Vault`` itself.
    public func writeStream(to path: VaultPath) async throws(StorageError) -> VaultWriteStream {
        VaultWriteStream(path: path, vault: self)
    }

    /// - Note: v0.5 decrypts the full payload up front — see the "Honest limits" note on ``Vault``.
    public func readStream(from path: VaultPath) async throws(StorageError) -> VaultReadStream {
        VaultReadStream(data: try await read(from: path))
    }

    // MARK: - Destruction

    /// Destroys the vault AND its master key. Irreversible; named accordingly.
    public func destroyVaultAndAllContents() async throws(StorageError) {
        try? await keychain.removeSecret(for: masterKeyItemKey)
        do { try FileManager.default.removeItem(at: directoryURL) }
        catch { throw StorageError.underlying(error) }
    }

    // MARK: - Internals

    private func deriveFileKey(salt: Data) throws(StorageError) -> SymmetricKey {
        let derived = KeyDerivation.hkdf(
            from: masterKeyBytes, salt: salt, info: Vault.fileKeyInfo, outputByteCount: 32
        )
        do { return try SymmetricKey(secureBytes: derived) }
        catch { throw StorageError.underlying(error) }
    }

    private func persistManifest() throws(StorageError) {
        do {
            let json = try JSONEncoder().encode(manifest)
            let sealed = try deriveFileKey(salt: Vault.manifestKeySalt).seal(json)
            try sealed.combinedRepresentation.write(to: manifestURL, options: .atomic)
            try Vault.applyProtection(fileProtection, to: manifestURL)
        } catch let error as StorageError {
            throw error
        } catch {
            throw StorageError.underlying(error)
        }
    }

    /// A fixed (non-secret, non-random) salt for the manifest's own key: the manifest is a
    /// single, always-present artifact, not one of many interchangeable per-file entries, so
    /// there's no benefit to randomizing it the way `Entry.keySalt` is randomized per file.
    private static let manifestKeySalt = Data("bolour.securestorage.manifest-key.v1".utf8)

    private static func directoryURL(for name: VaultName) throws(StorageError) -> URL {
        guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        else { throw StorageError.underlying(VaultPathError.absolutePath("no Application Support directory")) }
        return appSupport.appendingPathComponent("BolourSecurity/Vaults/\(name.rawValue)", isDirectory: true)
    }

    private static func ensureDirectory(_ url: URL, protection: FileProtectionType) throws(StorageError) {
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            try applyProtection(protection, to: url)
        } catch { throw StorageError.underlying(error) }
    }

    private static func applyProtection(_ protection: FileProtectionType, to url: URL) throws {
        do {
            try FileManager.default.setAttributes([.protectionKey: protection], ofItemAtPath: url.path)
        } catch {
            #if os(macOS)
            let underlying = (error as NSError).userInfo[NSUnderlyingErrorKey] as? NSError
            if underlying?.domain == NSPOSIXErrorDomain, underlying?.code == Int(EINVAL) {
                // Data Protection classes are an iOS-family feature; macOS support depends on
                // volume/FileVault configuration and is simply absent on many Macs — including
                // this package's own CI runners. Failing here would make Vault unusable on
                // those machines even though the actual confidentiality boundary is the
                // AES-GCM sealing applied to every artifact, not this OS attribute. Best-effort
                // only on macOS, and only for this specific "unsupported here" failure — every
                // other platform, and every other error, still fails closed.
                return
            }
            #endif
            throw error
        }
    }

    private static func loadOrCreateMasterKey(
        keychain: Keychain, itemKey: ItemKey, presence: PresenceRequirement, context: (any PresenceAuthenticated)?
    ) async throws(StorageError) -> SecureBytes {
        do {
            if let existing = try await keychain.secret(for: itemKey, context: context) {
                guard existing.count == 32 else {
                    throw StorageError.masterKeyUnavailable(reason: .corruptStoredKey)
                }
                return existing
            }
            let fresh = SecureRandom.bytes(count: 32)
            try await keychain.store(fresh, for: itemKey, presence: presence)
            return fresh
        } catch let error as StorageError {
            throw error
        } catch {
            throw StorageError.underlying(error)
        }
    }

    private static func loadOrCreateManifest(
        at url: URL, masterKeyBytes: SecureBytes, fileProtection: FileProtectionType
    ) throws(StorageError) -> VaultManifest {
        let derived = KeyDerivation.hkdf(
            from: masterKeyBytes, salt: manifestKeySalt, info: fileKeyInfo, outputByteCount: 32
        )
        let manifestKey: SymmetricKey
        do { manifestKey = try SymmetricKey(secureBytes: derived) }
        catch { throw StorageError.underlying(error) }

        guard let raw = try? Data(contentsOf: url) else {
            return VaultManifest()
        }
        do {
            let sealed = try SealedMessage(combinedRepresentation: raw)
            let json = try manifestKey.open(sealed)
            return try JSONDecoder().decode(VaultManifest.self, from: json)
        } catch {
            throw StorageError.integrityCheckFailed(.root)
        }
    }
}
