import Foundation
import Security
import BolourSecurityCore

/// Cryptographically secure randomness, backed by `SecRandomCopyBytes`.
public enum SecureRandom {

    /// `count` random bytes as ``SecureBytes``.
    public static func bytes(count: Int) -> SecureBytes {
        SecureBytes(randomBytes(count: count))
    }

    /// `count` random bytes as `Data`.
    public static func data(count: Int) -> Data {
        Data(randomBytes(count: count))
    }

    /// An unbiased random value in `range`, rejection-sampled by the standard library over a
    /// cryptographically secure generator.
    public static func number<T: FixedWidthInteger>(in range: Range<T>) -> T {
        precondition(!range.isEmpty, "range must be non-empty")
        var generator = SecureRandomNumberGenerator()
        return T.random(in: range, using: &generator)
    }

    private static func randomBytes(count: Int) -> [UInt8] {
        precondition(count >= 0, "count must be non-negative")
        var buffer = [UInt8](repeating: 0, count: count)
        guard count > 0 else { return buffer }
        let status = buffer.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed with status \(status)")
        return buffer
    }
}

/// A `RandomNumberGenerator` sourced from `SecRandomCopyBytes`.
struct SecureRandomNumberGenerator: RandomNumberGenerator {
    mutating func next() -> UInt64 {
        var value: UInt64 = 0
        let status = withUnsafeMutableBytes(of: &value) {
            SecRandomCopyBytes(kSecRandomDefault, 8, $0.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed with status \(status)")
        return value
    }
}
