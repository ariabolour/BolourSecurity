import Testing
import Foundation
import BolourCertificates

@Suite("Certificate parsing")
struct CertificateParsingTests {

    @Test("parses a leaf certificate's fields")
    func leaf() throws {
        let leaf = try Fixture.certificate("leaf-valid")
        #expect(leaf.subject.commonName == "valid.boloursecurity.test")
        #expect(leaf.isCertificateAuthority == false)
        #expect(leaf.subjectAlternativeNames.contains(.dnsName("valid.boloursecurity.test")))
        #expect(leaf.publicKeyInfo.algorithmOID == "1.2.840.10045.2.1")   // ecPublicKey
        #expect(leaf.validity.contains(Date()))                            // currently valid
    }

    @Test("parses a CA certificate and flags basic constraints")
    func root() throws {
        let root = try Fixture.certificate("root")
        #expect(root.isCertificateAuthority == true)
        #expect(root.subject.commonName == "BolourSecurity Test Root")
        #expect(root.subject.organizationName == "BolourSecurity")
    }

    @Test("DER representation round-trips through re-parsing")
    func roundTrip() throws {
        let leaf = try Fixture.certificate("leaf-valid")
        let reparsed = try Certificate(derEncoded: leaf.derRepresentation)
        #expect(reparsed == leaf)
    }

    @Test("PEM and DER parse to the same certificate")
    func pem() throws {
        let der = try Fixture.der("leaf-valid")
        let pem = "-----BEGIN CERTIFICATE-----\n"
            + der.base64EncodedString(options: .lineLength64Characters)
            + "\n-----END CERTIFICATE-----"
        #expect(try Certificate(pemEncoded: pem) == Certificate(derEncoded: der))
    }
}
