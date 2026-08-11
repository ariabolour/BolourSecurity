import Foundation
import CryptoKit

/// A SHA-256 digest — 32 bytes of public hash output. Not a secret, so it prints as hex.
public struct Digest256: Sendable, Hashable, ContiguousBytes, CustomStringConvertible {
    private let bytes: [UInt8]
    init(_ digest: CryptoKit.SHA256.Digest) { bytes = Array(digest) }
    init(bytes: [UInt8]) { self.bytes = bytes }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    public var description: String { bytes.hexString }
}

/// A SHA-384 digest — 48 bytes of public hash output.
public struct Digest384: Sendable, Hashable, ContiguousBytes, CustomStringConvertible {
    private let bytes: [UInt8]
    init(_ digest: CryptoKit.SHA384.Digest) { bytes = Array(digest) }
    init(bytes: [UInt8]) { self.bytes = bytes }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    public var description: String { bytes.hexString }
}

/// A SHA-512 digest — 64 bytes of public hash output.
public struct Digest512: Sendable, Hashable, ContiguousBytes, CustomStringConvertible {
    private let bytes: [UInt8]
    init(_ digest: CryptoKit.SHA512.Digest) { bytes = Array(digest) }
    init(bytes: [UInt8]) { self.bytes = bytes }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    public var description: String { bytes.hexString }
}

extension Sequence where Element == UInt8 {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
