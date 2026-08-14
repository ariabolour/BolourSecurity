import Foundation
import BlurSecurityCore

/// A token or credential with issuance/expiry metadata — the value `TokenStore` persists.
public struct StoredToken: Sendable, SecretConvertible {
    public let value: SecureBytes
    let issuedAt: Date
    public let expiresAt: Date?

    public init(value: SecureBytes, issuedAt: Date = .now, expiresAt: Date?) {
        self.value = value
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }

    /// Whether `expiresAt` has passed. `nil` (no expiry) is never expired.
    public var isExpired: Bool {
        guard let expiresAt else { return false }
        return expiresAt <= Date()
    }

    // MARK: SecretConvertible — versioned wire form: [version][issuedAt][hasExpiry][expiresAt?][value]

    private static let currentVersion: UInt8 = 1

    public func secureBytesRepresentation() throws -> SecureBytes {
        var out = Data([StoredToken.currentVersion])
        out.append(contentsOf: withUnsafeBytes(of: issuedAt.timeIntervalSince1970) { Data($0) })
        if let expiresAt {
            out.append(1)
            out.append(contentsOf: withUnsafeBytes(of: expiresAt.timeIntervalSince1970) { Data($0) })
        } else {
            out.append(0)
        }
        out.append(value.dangerouslyExportBytes())
        return SecureBytes(out)
    }

    public init(secureBytes: SecureBytes) throws {
        let data = secureBytes.dangerouslyExportBytes()
        var index = data.startIndex
        func take(_ count: Int) throws -> Data {
            guard data.distance(from: index, to: data.endIndex) >= count else {
                throw StoredTokenDecodingError.truncated
            }
            let range = index..<data.index(index, offsetBy: count)
            defer { index = range.upperBound }
            return data.subdata(in: range)
        }
        func takeDouble() throws -> Double {
            let bytes = try take(MemoryLayout<Double>.size)
            return bytes.withUnsafeBytes { $0.load(as: Double.self) }
        }

        guard try take(1).first == StoredToken.currentVersion else {
            throw StoredTokenDecodingError.unsupportedVersion
        }
        let issuedAt = Date(timeIntervalSince1970: try takeDouble())
        let hasExpiry = try take(1).first == 1
        let expiresAt: Date? = hasExpiry ? Date(timeIntervalSince1970: try takeDouble()) : nil
        let value = SecureBytes(data.subdata(in: index..<data.endIndex))

        self.init(value: value, issuedAt: issuedAt, expiresAt: expiresAt)
    }
}

enum StoredTokenDecodingError: Error, Sendable {
    case truncated
    case unsupportedVersion
}
