/// Parameters for password-based key derivation (PBKDF2-HMAC-SHA256).
public struct PasswordHashingParameters: Sendable, Hashable {
    /// The PBKDF2 iteration count. Higher is slower and stronger.
    public var iterations: Int
    /// The derived key length in bytes.
    public var outputByteCount: Int

    public init(iterations: Int, outputByteCount: Int = 32) {
        self.iterations = iterations
        self.outputByteCount = outputByteCount
    }

    /// The enforced minimum iteration count; parameters below this are rejected.
    public static let minimumIterations = 100_000

    /// The default: 210,000 iterations (OWASP 2023 guidance for PBKDF2-HMAC-SHA256), 32-byte output.
    /// The default is reviewed each release.
    public static let `default` = PasswordHashingParameters(iterations: 210_000, outputByteCount: 32)
}
