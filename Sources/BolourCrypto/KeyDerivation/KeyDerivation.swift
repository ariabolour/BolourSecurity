import Foundation
import CryptoKit
import CommonCrypto
import BolourSecurityCore

/// Key-derivation functions: HKDF for high-entropy inputs, PBKDF2 for passwords.
public enum KeyDerivation {

    /// HKDF-SHA256: derives `outputByteCount` bytes from high-entropy `secret`.
    public static func hkdf(
        from secret: SecureBytes,
        salt: some DataProtocol,
        info: some DataProtocol,
        outputByteCount: Int
    ) -> SecureBytes {
        let inputKey = secret.withUnsafeBytes { CryptoKit.SymmetricKey(data: Data($0)) }
        let derived = CryptoKit.HKDF<CryptoKit.SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: Data(salt),
            info: Data(info),
            outputByteCount: outputByteCount
        )
        return derived.withUnsafeBytes { SecureBytes(Data($0)) }
    }

    /// PBKDF2-HMAC-SHA256: derives a key from a low-entropy `password`.
    ///
    /// - Note: PBKDF2 is the strongest password KDF in Apple's SDKs. Memory-hard KDFs (Argon2,
    ///   scrypt) are unavailable without third-party code (forbidden by ADR-0002); apps needing
    ///   those should hash passwords server-side.
    public static func fromPassword(
        _ password: String,
        salt: some DataProtocol,
        parameters: PasswordHashingParameters = .default
    ) throws(CryptoError) -> SecureBytes {
        guard parameters.iterations >= PasswordHashingParameters.minimumIterations else {
            throw CryptoError.insecureParameters(
                reason: "iterations (\(parameters.iterations)) below the floor of \(PasswordHashingParameters.minimumIterations)"
            )
        }
        guard parameters.outputByteCount > 0 else {
            throw CryptoError.keyDerivationFailed
        }

        let passwordData = Data(password.utf8)
        let saltData = Data(salt)
        var derived = [UInt8](repeating: 0, count: parameters.outputByteCount)

        let status: Int32 = derived.withUnsafeMutableBytes { derivedPtr in
            saltData.withUnsafeBytes { saltPtr in
                passwordData.withUnsafeBytes { passwordPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordPtr.baseAddress?.assumingMemoryBound(to: CChar.self),
                        passwordData.count,
                        saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        saltData.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(parameters.iterations),
                        derivedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        parameters.outputByteCount
                    )
                }
            }
        }

        guard status == kCCSuccess else { throw CryptoError.keyDerivationFailed }
        let result = SecureBytes(derived)
        // Best-effort wipe of the temporary buffer.
        derived.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress, raw.count > 0 { _ = memset_s(base, raw.count, 0, raw.count) }
        }
        return result
    }
}
