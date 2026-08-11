import Foundation

/// One DER TLV element: its tag, its content octets, and its full (tag+length+content) encoding.
struct DERElement {
    let tag: UInt8
    let value: [UInt8]     // content octets
    let encoded: [UInt8]   // full element, for raw substructure extraction (e.g. SPKI)
}

/// A minimal, total DER scanner over a byte buffer.
///
/// It handles exactly the definite-length TLV structure X.509 needs; indefinite lengths (not valid
/// DER) and over-large or out-of-bounds lengths are rejected. Every read is bounds-checked, so on any
/// malformed input it throws `CertificateError.malformedEncoding` — it never crashes, hangs, or
/// over-allocates. Nesting is walked with fresh scanners over already-bounded sub-buffers, so there is
/// no unbounded recursion.
struct DERScanner {
    private let bytes: [UInt8]
    private var position: Int

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
        self.position = 0
    }

    var isAtEnd: Bool { position >= bytes.count }

    /// Reads the next element and advances past it.
    mutating func readElement() throws(CertificateError) -> DERElement {
        let start = position
        guard position < bytes.count else { throw CertificateError.malformedEncoding(detail: .truncated) }
        let tag = bytes[position]
        position += 1

        guard position < bytes.count else { throw CertificateError.malformedEncoding(detail: .truncated) }
        let lengthByte = bytes[position]
        position += 1

        let length: Int
        if lengthByte & 0x80 == 0 {
            length = Int(lengthByte)
        } else {
            let byteCount = Int(lengthByte & 0x7f)
            guard byteCount != 0 else { throw CertificateError.malformedEncoding(detail: .indefiniteLength) }
            guard byteCount <= 4 else { throw CertificateError.malformedEncoding(detail: .lengthTooLarge) }
            var accumulated = 0
            for _ in 0..<byteCount {
                guard position < bytes.count else { throw CertificateError.malformedEncoding(detail: .truncated) }
                accumulated = (accumulated << 8) | Int(bytes[position])
                position += 1
            }
            length = accumulated
        }

        guard length >= 0, length <= bytes.count - position else {
            throw CertificateError.malformedEncoding(detail: .truncated)
        }
        let valueStart = position
        position += length
        return DERElement(
            tag: tag,
            value: Array(bytes[valueStart..<valueStart + length]),
            encoded: Array(bytes[start..<position])
        )
    }

    /// Reads an element and asserts its tag, throwing `.unexpectedTag` otherwise.
    mutating func readElement(expecting tag: UInt8) throws(CertificateError) -> DERElement {
        let element = try readElement()
        guard element.tag == tag else { throw CertificateError.malformedEncoding(detail: .unexpectedTag) }
        return element
    }
}

/// DER tag constants used by the X.509 parser.
enum DERTag {
    static let boolean: UInt8 = 0x01
    static let integer: UInt8 = 0x02
    static let bitString: UInt8 = 0x03
    static let octetString: UInt8 = 0x04
    static let objectIdentifier: UInt8 = 0x06
    static let utf8String: UInt8 = 0x0c
    static let printableString: UInt8 = 0x13
    static let ia5String: UInt8 = 0x16
    static let utcTime: UInt8 = 0x17
    static let generalizedTime: UInt8 = 0x18
    static let sequence: UInt8 = 0x30
    static let set: UInt8 = 0x31
    static let contextVersion: UInt8 = 0xa0     // [0] EXPLICIT version
    static let contextExtensions: UInt8 = 0xa3  // [3] EXPLICIT extensions

    // SubjectAltName GeneralName choices (primitive context tags)
    static let generalNameDNS: UInt8 = 0x82     // [2] dNSName
    static let generalNameURI: UInt8 = 0x86     // [6] uniformResourceIdentifier
    static let generalNameIP: UInt8 = 0x87      // [7] iPAddress
}

extension DERElement {
    /// Decodes an OBJECT IDENTIFIER's content into dotted-decimal form (e.g. "2.5.4.3").
    func objectIdentifierString() throws(CertificateError) -> String {
        guard tag == DERTag.objectIdentifier, let first = value.first else {
            throw CertificateError.malformedEncoding(detail: .invalidObjectIdentifier)
        }
        var components = ["\(first / 40)", "\(first % 40)"]
        var current = 0
        var pending = false
        for byte in value.dropFirst() {
            current = (current << 7) | Int(byte & 0x7f)
            pending = true
            if byte & 0x80 == 0 {
                components.append("\(current)")
                current = 0
                pending = false
            }
        }
        guard !pending else { throw CertificateError.malformedEncoding(detail: .invalidObjectIdentifier) }
        return components.joined(separator: ".")
    }

    /// Decodes a directory/IA5 string element as UTF-8 (a superset of the ASCII string types we see).
    var stringValue: String {
        String(decoding: value, as: UTF8.self)
    }
}
