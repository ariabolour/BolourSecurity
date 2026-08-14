import Foundation

/// A read handle returned by `Vault.readStream(from:)`.
///
/// - Note: v0.5 decrypts the full payload up front and serves it from an in-memory buffer —
///   see the "Honest limits" note on ``Vault``.
public actor VaultReadStream {
    private let data: Data
    private var offset = 0

    init(data: Data) {
        self.data = data
    }

    /// Returns up to `maxLength` bytes, or `nil` at end of stream.
    public func read(maxLength: Int) -> Data? {
        guard offset < data.count else { return nil }
        let end = min(offset + maxLength, data.count)
        defer { offset = end }
        return data.subdata(in: offset..<end)
    }
}
