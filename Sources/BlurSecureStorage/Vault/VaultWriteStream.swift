import Foundation

/// A write handle returned by `Vault.writeStream(to:)`.
///
/// - Note: v0.5 buffers every appended chunk in memory and seals the whole payload in
///   `finish()` — see the "Honest limits" note on ``Vault``.
public actor VaultWriteStream {
    private var buffer = Data()
    private let path: VaultPath
    private let vault: Vault

    init(path: VaultPath, vault: Vault) {
        self.path = path
        self.vault = vault
    }

    /// Appends a chunk to the payload.
    public func write(_ chunk: Data) {
        buffer.append(chunk)
    }

    /// Seals and persists everything written so far.
    public func finish() async throws(StorageError) {
        try await vault.write(buffer, to: path)
    }
}
