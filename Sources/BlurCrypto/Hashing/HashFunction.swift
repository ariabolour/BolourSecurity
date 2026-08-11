import Foundation
import CryptoKit

/// A hash function usable with ``HMAC``. Conformed to by ``SHA256``, ``SHA384``, ``SHA512``.
///
/// The underscore-prefixed members are an implementation detail (they curate CryptoKit behind a
/// Data-only surface so no CryptoKit type leaks into the public API) — do not call or conform.
public protocol BlurHashFunction: Sendable {
    static func _authenticationCode(for data: Data, keyBytes: Data) -> Data
    static func _isValidAuthenticationCode(_ code: Data, for data: Data, keyBytes: Data) -> Bool
}

/// SHA-256 hashing.
public enum SHA256: BlurHashFunction {
    /// The SHA-256 digest of `data`.
    public static func digest(of data: some DataProtocol) -> Digest256 {
        Digest256(CryptoKit.SHA256.hash(data: Data(data)))
    }
    /// The SHA-256 digest of the file at `url`, streamed in constant memory.
    public static func digest(ofFileAt url: URL) async throws(CryptoError) -> Digest256 {
        Digest256(try FileHashing.digest(CryptoKit.SHA256.self, ofFileAt: url))
    }
    public static func _authenticationCode(for data: Data, keyBytes: Data) -> Data {
        Data(CryptoKit.HMAC<CryptoKit.SHA256>.authenticationCode(for: data, using: .init(data: keyBytes)))
    }
    public static func _isValidAuthenticationCode(_ code: Data, for data: Data, keyBytes: Data) -> Bool {
        CryptoKit.HMAC<CryptoKit.SHA256>.isValidAuthenticationCode(code, authenticating: data, using: .init(data: keyBytes))
    }
}

/// SHA-384 hashing.
public enum SHA384: BlurHashFunction {
    /// The SHA-384 digest of `data`.
    public static func digest(of data: some DataProtocol) -> Digest384 {
        Digest384(CryptoKit.SHA384.hash(data: Data(data)))
    }
    /// The SHA-384 digest of the file at `url`, streamed in constant memory.
    public static func digest(ofFileAt url: URL) async throws(CryptoError) -> Digest384 {
        Digest384(try FileHashing.digest(CryptoKit.SHA384.self, ofFileAt: url))
    }
    public static func _authenticationCode(for data: Data, keyBytes: Data) -> Data {
        Data(CryptoKit.HMAC<CryptoKit.SHA384>.authenticationCode(for: data, using: .init(data: keyBytes)))
    }
    public static func _isValidAuthenticationCode(_ code: Data, for data: Data, keyBytes: Data) -> Bool {
        CryptoKit.HMAC<CryptoKit.SHA384>.isValidAuthenticationCode(code, authenticating: data, using: .init(data: keyBytes))
    }
}

/// SHA-512 hashing.
public enum SHA512: BlurHashFunction {
    /// The SHA-512 digest of `data`.
    public static func digest(of data: some DataProtocol) -> Digest512 {
        Digest512(CryptoKit.SHA512.hash(data: Data(data)))
    }
    /// The SHA-512 digest of the file at `url`, streamed in constant memory.
    public static func digest(ofFileAt url: URL) async throws(CryptoError) -> Digest512 {
        Digest512(try FileHashing.digest(CryptoKit.SHA512.self, ofFileAt: url))
    }
    public static func _authenticationCode(for data: Data, keyBytes: Data) -> Data {
        Data(CryptoKit.HMAC<CryptoKit.SHA512>.authenticationCode(for: data, using: .init(data: keyBytes)))
    }
    public static func _isValidAuthenticationCode(_ code: Data, for data: Data, keyBytes: Data) -> Bool {
        CryptoKit.HMAC<CryptoKit.SHA512>.isValidAuthenticationCode(code, authenticating: data, using: .init(data: keyBytes))
    }
}

/// Streams a file through a CryptoKit hash function in fixed-size chunks (constant memory).
enum FileHashing {
    static func digest<H: CryptoKit.HashFunction>(
        _ type: H.Type, ofFileAt url: URL
    ) throws(CryptoError) -> H.Digest {
        let handle: FileHandle
        do { handle = try FileHandle(forReadingFrom: url) }
        catch { throw CryptoError.fileUnreadable(url) }
        defer { try? handle.close() }

        var hasher = H()
        do {
            while let chunk = try handle.read(upToCount: 1 << 16), !chunk.isEmpty {
                hasher.update(data: chunk)
            }
        } catch {
            throw CryptoError.fileUnreadable(url)
        }
        return hasher.finalize()
    }
}
