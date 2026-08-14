import Foundation
import Security
import BlurCertificates

extension CertificateChain {
    /// Builds a chain from the certificates a `SecTrust` presented (leaf first), reparsing each
    /// one through `BlurCertificates.Certificate` for introspection. This is a second, honest
    /// parse of bytes the OS already holds — not a second trust decision.
    init(presentedBy trust: SecTrust) throws(CertificateError) {
        guard let secCertificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              !secCertificates.isEmpty
        else {
            throw CertificateError.malformedEncoding(detail: .notACertificate)
        }
        var certificates: [Certificate] = []
        for secCertificate in secCertificates {
            let der = SecCertificateCopyData(secCertificate) as Data
            certificates.append(try Certificate(derEncoded: der))
        }
        self.init(certificates)
    }
}
