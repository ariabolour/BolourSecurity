import Foundation

/// A read handle returned by `Vault.readStream(from:)`.
///
/// - Note: v0.5 decrypts the full payload up front and serves it from an in-memory buffer —
///   see the "Honest limits" note on ``Vault``.
public actor VaultReadStream {
    // Normalized to a plain, always-zero-indexed buffer at init: `Data` values handed back by
    // system APIs (CryptoKit's AEAD open included) are not guaranteed to start at index 0 — a
    // real bug caught elsewhere in this codebase by literal-integer `subdata(in:)` ranges
    // crashing against a `Data` whose `startIndex` turned out to be nonzero. Slicing `[UInt8]`
    // instead of `Data` sidesteps the whole index-space question.
    private let bytes: [UInt8]
    private var offset = 0

    init(data: Data) {
        self.bytes = [UInt8](data)
    }

    /// Returns up to `maxLength` bytes, or `nil` at end of stream.
    public func read(maxLength: Int) -> Data? {
        guard offset < bytes.count else { return nil }
        let end = min(offset + maxLength, bytes.count)
        defer { offset = end }
        return Data(bytes[offset..<end])
    }
}
