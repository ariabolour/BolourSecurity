import Foundation

/// A typed view of an X.509 certificate — the fields that matter for validation and pinning.
///
/// Parsing is done by a minimal in-tree DER reader used for *introspection and SPKI extraction only*.
/// It is never a trust-decision engine: chain validation is `SecTrust`'s job (see ``TrustEvaluator``).
public struct Certificate: Sendable, Hashable {
    public let subject: DistinguishedName
    public let issuer: DistinguishedName
    public let validity: ClosedRange<Date>
    public let subjectAlternativeNames: [SubjectAlternativeName]
    public let publicKeyInfo: SubjectPublicKeyInfo
    public let isCertificateAuthority: Bool
    public let derRepresentation: Data

    private init(
        subject: DistinguishedName, issuer: DistinguishedName, validity: ClosedRange<Date>,
        subjectAlternativeNames: [SubjectAlternativeName], publicKeyInfo: SubjectPublicKeyInfo,
        isCertificateAuthority: Bool, derRepresentation: Data
    ) {
        self.subject = subject
        self.issuer = issuer
        self.validity = validity
        self.subjectAlternativeNames = subjectAlternativeNames
        self.publicKeyInfo = publicKeyInfo
        self.isCertificateAuthority = isCertificateAuthority
        self.derRepresentation = derRepresentation
    }

    /// Parses a DER-encoded certificate.
    public init(derEncoded der: Data) throws(CertificateError) {
        self = try Certificate.parse([UInt8](der))
    }

    /// Parses a PEM-encoded certificate.
    public init(pemEncoded pem: String) throws(CertificateError) {
        self = try Certificate.parse([UInt8](Certificate.der(fromPEM: pem)))
    }

    public static func == (lhs: Certificate, rhs: Certificate) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
    public func hash(into hasher: inout Hasher) {
        hasher.combine(derRepresentation)
    }
}

// MARK: - X.509 / DER parsing (introspection only)

private extension Certificate {

    static func der(fromPEM pem: String) throws(CertificateError) -> Data {
        let base64 = pem
            .split(whereSeparator: \.isNewline)
            .filter { !$0.hasPrefix("-----") }
            .joined()
        guard !base64.isEmpty, let data = Data(base64Encoded: base64) else {
            throw CertificateError.malformedEncoding(detail: .invalidPEM)
        }
        return data
    }

    static func parse(_ der: [UInt8]) throws(CertificateError) -> Certificate {
        var top = DERScanner(der)
        let certificate = try top.readElement(expecting: DERTag.sequence)

        var certificateBody = DERScanner(certificate.value)
        let tbs = try certificateBody.readElement(expecting: DERTag.sequence)

        var tbsBody = DERScanner(tbs.value)
        let element = try tbsBody.readElement()          // version [0] or serialNumber
        if element.tag == DERTag.contextVersion {
            _ = try tbsBody.readElement()                // serialNumber
        }
        _ = try tbsBody.readElement(expecting: DERTag.sequence)              // signature algorithm
        let issuerElement = try tbsBody.readElement(expecting: DERTag.sequence)
        let validityElement = try tbsBody.readElement(expecting: DERTag.sequence)
        let subjectElement = try tbsBody.readElement(expecting: DERTag.sequence)
        let spkiElement = try tbsBody.readElement(expecting: DERTag.sequence)

        var extensionsElement: DERElement?
        while !tbsBody.isAtEnd {
            let next = try tbsBody.readElement()
            if next.tag == DERTag.contextExtensions { extensionsElement = next }
        }

        var subjectAlternativeNames: [SubjectAlternativeName] = []
        var isCertificateAuthority = false
        if let extensionsElement {
            (subjectAlternativeNames, isCertificateAuthority) = try parseExtensions(extensionsElement)
        }

        return Certificate(
            subject: try parseName(subjectElement),
            issuer: try parseName(issuerElement),
            validity: try parseValidity(validityElement),
            subjectAlternativeNames: subjectAlternativeNames,
            publicKeyInfo: try parseSPKI(spkiElement),
            isCertificateAuthority: isCertificateAuthority,
            derRepresentation: Data(der)
        )
    }

    static func parseName(_ element: DERElement) throws(CertificateError) -> DistinguishedName {
        var attributes: [DistinguishedName.Attribute] = []
        var rdnSequence = DERScanner(element.value)
        while !rdnSequence.isAtEnd {
            let rdn = try rdnSequence.readElement(expecting: DERTag.set)
            var set = DERScanner(rdn.value)
            while !set.isAtEnd {
                let atv = try set.readElement(expecting: DERTag.sequence)
                var body = DERScanner(atv.value)
                let oid = try body.readElement(expecting: DERTag.objectIdentifier).objectIdentifierString()
                let value = try body.readElement()
                attributes.append(.init(oid: oid, value: value.stringValue))
            }
        }
        return DistinguishedName(attributes: attributes)
    }

    static func parseValidity(_ element: DERElement) throws(CertificateError) -> ClosedRange<Date> {
        var body = DERScanner(element.value)
        let notBefore = try parseTime(body.readElement())
        let notAfter = try parseTime(body.readElement())
        guard notBefore <= notAfter else { throw CertificateError.malformedEncoding(detail: .invalidTime) }
        return notBefore...notAfter
    }

    static func parseTime(_ element: DERElement) throws(CertificateError) -> Date {
        let string = String(decoding: element.value, as: UTF8.self)
        let digits = Array(string)
        var components = DateComponents()

        func number(_ range: ClosedRange<Int>) -> Int? {
            guard range.upperBound < digits.count else { return nil }
            return Int(String(digits[range]))
        }

        switch element.tag {
        case DERTag.utcTime:
            guard string.count == 13, string.hasSuffix("Z"),
                  let yy = number(0...1), let mo = number(2...3), let dd = number(4...5),
                  let hh = number(6...7), let mi = number(8...9), let ss = number(10...11)
            else { throw CertificateError.malformedEncoding(detail: .invalidTime) }
            components.year = yy < 50 ? 2000 + yy : 1900 + yy
            components.month = mo; components.day = dd
            components.hour = hh; components.minute = mi; components.second = ss
        case DERTag.generalizedTime:
            guard string.count == 15, string.hasSuffix("Z"),
                  let yyyy = number(0...3), let mo = number(4...5), let dd = number(6...7),
                  let hh = number(8...9), let mi = number(10...11), let ss = number(12...13)
            else { throw CertificateError.malformedEncoding(detail: .invalidTime) }
            components.year = yyyy; components.month = mo; components.day = dd
            components.hour = hh; components.minute = mi; components.second = ss
        default:
            throw CertificateError.malformedEncoding(detail: .invalidTime)
        }

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        guard let date = calendar.date(from: components) else {
            throw CertificateError.malformedEncoding(detail: .invalidTime)
        }
        return date
    }

    static func parseSPKI(_ element: DERElement) throws(CertificateError) -> SubjectPublicKeyInfo {
        var body = DERScanner(element.value)
        let algorithm = try body.readElement(expecting: DERTag.sequence)
        var algorithmBody = DERScanner(algorithm.value)
        let oid = try algorithmBody.readElement(expecting: DERTag.objectIdentifier).objectIdentifierString()
        return SubjectPublicKeyInfo(algorithmOID: oid, derRepresentation: Data(element.encoded))
    }

    static func parseExtensions(
        _ element: DERElement
    ) throws(CertificateError) -> ([SubjectAlternativeName], Bool) {
        var explicitWrapper = DERScanner(element.value)          // [3] EXPLICIT wraps the SEQUENCE
        let sequence = try explicitWrapper.readElement(expecting: DERTag.sequence)
        var body = DERScanner(sequence.value)

        var sans: [SubjectAlternativeName] = []
        var isCA = false
        while !body.isAtEnd {
            let ext = try body.readElement(expecting: DERTag.sequence)
            var fields = DERScanner(ext.value)
            let oid = try fields.readElement(expecting: DERTag.objectIdentifier).objectIdentifierString()
            var extnValue = try fields.readElement()
            if extnValue.tag == DERTag.boolean {                 // optional critical flag
                extnValue = try fields.readElement()
            }
            guard extnValue.tag == DERTag.octetString else {
                throw CertificateError.malformedEncoding(detail: .unexpectedTag)
            }
            switch oid {
            case "2.5.29.17": sans = try parseSubjectAltNames(extnValue.value)
            case "2.5.29.19": isCA = try parseBasicConstraints(extnValue.value)
            default: break
            }
        }
        return (sans, isCA)
    }

    static func parseSubjectAltNames(_ octets: [UInt8]) throws(CertificateError) -> [SubjectAlternativeName] {
        var scanner = DERScanner(octets)
        let sequence = try scanner.readElement(expecting: DERTag.sequence)
        var body = DERScanner(sequence.value)
        var names: [SubjectAlternativeName] = []
        while !body.isAtEnd {
            let name = try body.readElement()
            switch name.tag {
            case DERTag.generalNameDNS: names.append(.dnsName(name.stringValue))
            case DERTag.generalNameURI: names.append(.uri(name.stringValue))
            case DERTag.generalNameIP: names.append(.ipAddress(Data(name.value)))
            default: break
            }
        }
        return names
    }

    static func parseBasicConstraints(_ octets: [UInt8]) throws(CertificateError) -> Bool {
        var scanner = DERScanner(octets)
        let sequence = try scanner.readElement(expecting: DERTag.sequence)
        var body = DERScanner(sequence.value)
        guard !body.isAtEnd else { return false }
        let first = try body.readElement()
        if first.tag == DERTag.boolean { return (first.value.first ?? 0) != 0 }
        return false
    }
}
