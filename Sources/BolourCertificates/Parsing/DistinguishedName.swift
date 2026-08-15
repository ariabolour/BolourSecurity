/// An X.500 distinguished name (a certificate's subject or issuer), as the attributes we surface.
public struct DistinguishedName: Sendable, Hashable, CustomStringConvertible {
    /// The relative distinguished-name attributes, in encounter order, as (OID, value) pairs.
    public let attributes: [Attribute]

    public struct Attribute: Sendable, Hashable {
        public let oid: String
        public let value: String
    }

    init(attributes: [Attribute]) { self.attributes = attributes }

    /// The most specific Common Name (OID 2.5.4.3), if present.
    public var commonName: String? { attributes.last { $0.oid == "2.5.4.3" }?.value }
    /// The Organization (OID 2.5.4.10), if present.
    public var organizationName: String? { attributes.last { $0.oid == "2.5.4.10" }?.value }

    public var description: String {
        commonName ?? organizationName ?? attributes.map { "\($0.oid)=\($0.value)" }.joined(separator: ", ")
    }
}
