import Foundation
import CryptoKit
import BolourSecurityCore

/// A 256-bit symmetric key for authenticated encryption.
///
/// Sealing always generates a fresh random nonce — no API accepts a caller-provided nonce, so
/// nonce reuse (the classic catastrophic GCM failure) is unrepresentable, not merely discouraged.
///
/// ```swift
/// let key = SymmetricKey.random()
/// let sealed = try key.seal(documentData)
/// let restored = try key.open(sealed)
/// ```
public struct SymmetricKey: Sendable {
    let cryptoKitKey: CryptoKit.SymmetricKey
    let suite: CipherSuite

    init(cryptoKitKey: CryptoKit.SymmetricKey, suite: CipherSuite) {
        self.cryptoKitKey = cryptoKitKey
        self.suite = suite
    }

    /// A fresh random key for `suite`.
    public static func random(_ suite: CipherSuite = .aes256GCM) -> SymmetricKey {
        SymmetricKey(cryptoKitKey: CryptoKit.SymmetricKey(size: .bits256), suite: suite)
    }

    /// A key from existing 256-bit (32-byte) secret material.
    public init(secureBytes: SecureBytes, suite: CipherSuite = .aes256GCM) throws(CryptoError) {
        guard secureBytes.count == 32 else {
            throw CryptoError.invalidKeySize(expected: 32, actual: secureBytes.count)
        }
        self.cryptoKitKey = secureBytes.withUnsafeBytes { CryptoKit.SymmetricKey(data: Data($0)) }
        self.suite = suite
    }

    /// The raw key bytes, for internal keyed-hash use.
    var rawKeyBytes: Data { cryptoKitKey.withUnsafeBytes { Data($0) } }

    // MARK: Seal

    /// Encrypts `plaintext` with a fresh random nonce.
    public func seal(_ plaintext: some DataProtocol) throws(CryptoError) -> SealedMessage {
        try sealImpl(Data(plaintext), aad: Data())
    }

    /// Encrypts `plaintext`, additionally authenticating `aad` (associated data that is
    /// authenticated but not encrypted).
    public func seal(
        _ plaintext: some DataProtocol, authenticating aad: some DataProtocol
    ) throws(CryptoError) -> SealedMessage {
        try sealImpl(Data(plaintext), aad: Data(aad))
    }

    private func sealImpl(_ plaintext: Data, aad: Data) throws(CryptoError) -> SealedMessage {
        do {
            switch suite {
            case .aes256GCM:
                let box = try AES.GCM.seal(plaintext, using: cryptoKitKey, authenticating: aad)
                guard let combined = box.combined else { throw CryptoError.sealFailed }
                return SealedMessage(suite: .aes256GCM, payload: combined)
            case .chaChaPoly:
                let box = try ChaChaPoly.seal(plaintext, using: cryptoKitKey, authenticating: aad)
                return SealedMessage(suite: .chaChaPoly, payload: box.combined)
            }
        } catch let error as CryptoError {
            throw error
        } catch {
            throw CryptoError.sealFailed
        }
    }

    // MARK: Open

    /// Decrypts a sealed message.
    public func open(_ message: SealedMessage) throws(CryptoError) -> Data {
        try openImpl(message, aad: Data())
    }

    /// Decrypts a sealed message, authenticating the same `aad` used to seal it.
    public func open(
        _ message: SealedMessage, authenticating aad: some DataProtocol
    ) throws(CryptoError) -> Data {
        try openImpl(message, aad: Data(aad))
    }

    private func openImpl(_ message: SealedMessage, aad: Data) throws(CryptoError) -> Data {
        guard message.suite == suite else {
            throw CryptoError.suiteMismatch(expected: suite, actual: message.suite)
        }
        do {
            switch suite {
            case .aes256GCM:
                let box = try AES.GCM.SealedBox(combined: message.payload)
                return try AES.GCM.open(box, using: cryptoKitKey, authenticating: aad)
            case .chaChaPoly:
                let box = try ChaChaPoly.SealedBox(combined: message.payload)
                return try ChaChaPoly.open(box, using: cryptoKitKey, authenticating: aad)
            }
        } catch {
            throw CryptoError.openFailed
        }
    }
}
