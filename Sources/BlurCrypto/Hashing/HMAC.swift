import Foundation

/// A message authentication code produced by ``HMAC``.
public struct AuthenticationCode: Sendable, Hashable, ContiguousBytes, CustomStringConvertible {
    let bytes: [UInt8]
    init(bytes: [UInt8]) { self.bytes = bytes }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    public var description: String { bytes.hexString }
}

/// Keyed-hash message authentication, parameterized by the hash function.
///
/// ```swift
/// let mac = HMAC<SHA256>.code(for: message, using: key)
/// let ok  = HMAC<SHA256>.isValidCode(mac, for: message, using: key)   // constant-time
/// ```
public enum HMAC<H: BlurHashFunction> {
    /// The authentication code for `data` under `key`.
    public static func code(for data: some DataProtocol, using key: SymmetricKey) -> AuthenticationCode {
        AuthenticationCode(bytes: Array(H._authenticationCode(for: Data(data), keyBytes: key.rawKeyBytes)))
    }

    /// Whether `code` is valid for `data` under `key`. Constant-time.
    public static func isValidCode(
        _ code: AuthenticationCode, for data: some DataProtocol, using key: SymmetricKey
    ) -> Bool {
        H._isValidAuthenticationCode(Data(code.bytes), for: Data(data), keyBytes: key.rawKeyBytes)
    }
}
