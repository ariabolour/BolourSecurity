import Foundation
import Security
import CryptoKit

/// A P-256 signing key whose private material lives entirely inside the Secure Enclave — never
/// readable by the app, a memory dump, or a backup. The flagship key type per
/// [ADR-0006](../../../docs/adr/0006-secure-enclave-first-key-design.md): hardware-backed is the
/// default wherever the operation permits it.
///
/// On hardware without a Secure Enclave (pre-T2 Intel Macs), ``create(tag:)`` throws
/// ``CryptoError/secureEnclaveUnavailable`` — it never silently substitutes a software key. Fall
/// back to `SigningKey<P256>.software()` explicitly; the call site then reads as the deliberate
/// choice it is.
public struct SecureEnclaveKey: Sendable {
    private let box: SecKeyBox
    public let tag: String

    private init(secKey: SecKey, tag: String) {
        self.box = SecKeyBox(secKey)
        self.tag = tag
    }

    /// Creates a fresh key, persisted in the Secure Enclave under `tag` (a caller-chosen,
    /// stable identifier — reuse it with ``load(tag:)`` to retrieve the same key later).
    public static func create(tag: String) throws(CryptoError) -> SecureEnclaveKey {
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil
        ) else {
            throw CryptoError.secureEnclaveOperationFailed(underlying: errSecParam)
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: access,
            ],
        ]

        var cfError: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
            // Apple does not document a stable OSStatus for "no Secure Enclave on this hardware"
            // distinctly from other creation failures, so any failure here is treated as
            // unavailability — the safe default per ADR-0006 (never silently fall back).
            throw CryptoError.secureEnclaveUnavailable
        }
        return SecureEnclaveKey(secKey: secKey, tag: tag)
    }

    /// Loads a previously created key by `tag`, or `nil` if none exists.
    public static func load(tag: String) throws(CryptoError) -> SecureEnclaveKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let secKey = result else {
            throw CryptoError.secureEnclaveOperationFailed(underlying: status)
        }
        // swiftlint:disable:next force_cast
        return SecureEnclaveKey(secKey: (secKey as! SecKey), tag: tag)
    }

    /// Removes the key from the Secure Enclave. Irreversible.
    public func destroy() throws(CryptoError) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CryptoError.secureEnclaveOperationFailed(underlying: status)
        }
    }

    /// The public key that verifies this key's signatures.
    public var verificationKey: VerificationKey<P256> {
        get throws(CryptoError) {
            guard let publicSecKey = SecKeyCopyPublicKey(box.secKey) else {
                throw CryptoError.secureEnclaveOperationFailed(underlying: errSecParam)
            }
            var cfError: Unmanaged<CFError>?
            guard let externalRepresentation = SecKeyCopyExternalRepresentation(publicSecKey, &cfError) else {
                throw CryptoError.secureEnclaveOperationFailed(underlying: errSecParam)
            }
            // SecKeyCopyExternalRepresentation returns the X9.63 form (0x04 ‖ X ‖ Y, 65 bytes)
            // for an EC public key. CryptoKit's own P256.Signing.PublicKey.rawRepresentation —
            // what VerificationKey<P256> actually validates against — is the *compact* form:
            // X ‖ Y with no leading tag byte, 64 bytes. Confirmed empirically (not assumed):
            // a standalone probe printed CryptoKit's rawRepresentation.count as 64 and its first
            // byte as an arbitrary coordinate byte, versus x963Representation.count as 65 with a
            // fixed 0x04 first byte. Dropping that one leading byte is the entire conversion.
            let compact = (externalRepresentation as Data).dropFirst()
            guard compact.count == 64 else {
                throw CryptoError.secureEnclaveOperationFailed(underlying: errSecParam)
            }
            return try VerificationKey(rawRepresentation: Data(compact))
        }
    }

    /// Signs `data` inside the Secure Enclave; the private key material never leaves it.
    public func signature(for data: some DataProtocol) throws(CryptoError) -> Signature<P256> {
        var cfError: Unmanaged<CFError>?
        guard let derSignature = SecKeyCreateSignature(
            box.secKey, .ecdsaSignatureMessageX962SHA256, Data(data) as CFData, &cfError
        ) else {
            throw CryptoError.signingFailed
        }
        // SecKeyCreateSignature returns a DER-encoded ECDSA signature; Signature<P256> (and the
        // software P256 path) speaks CryptoKit's raw r‖s form, so every Signature<P256> in the
        // ecosystem is interchangeable regardless of which key type produced it.
        do {
            let converted = try CryptoKit.P256.Signing.ECDSASignature(derRepresentation: derSignature as Data)
            return Signature(representation: converted.rawRepresentation)
        } catch {
            throw CryptoError.signingFailed
        }
    }
}

/// `SecKey` is a `CFTypeRef`; Apple documents `SecKey` instances as safe to use concurrently
/// once created (they're immutable handles to Keychain-resident material), so wrapping it as
/// `@unchecked Sendable` reflects the platform's own concurrency contract rather than papering
/// over a real race.
private final class SecKeyBox: @unchecked Sendable {
    let secKey: SecKey
    init(_ secKey: SecKey) { self.secKey = secKey }
}
