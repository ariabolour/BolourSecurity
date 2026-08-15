import Foundation
import Security
import BolourSecurityCore

/// A certificate chain as presented by a server (leaf first).
public struct CertificateChain: Sendable {
    public let certificates: [Certificate]
    public init(_ certificates: [Certificate]) { self.certificates = certificates }
}

/// Proof that a chain passed system trust (and any applicable pins) — the only chain type
/// `BolourNetworkSecurity` accepts as trusted.
public struct EvaluatedCertificateChain: Sendable {
    public let leaf: Certificate
    public let host: String
    public let evaluatedAt: Date
    /// The pin that matched, if a pinning policy applied to the host.
    public let matchedPin: SPKIHash?
}

/// Evaluates certificate chains against system trust, enforcing SPKI pins additively.
///
/// System trust (`SecTrust`) is the sole path-validation and hostname authority — we never
/// reimplement it. Pins are checked only *after* system trust passes, never instead of it.
public struct TrustEvaluator: TrustEvaluating, Sendable {
    private let pinningPolicies: [PinningPolicy]
    private let logger: (any SecurityEventLogger)?
    private let testAnchors: [Certificate]?

    public init(pinning: [PinningPolicy] = [], logger: (any SecurityEventLogger)? = nil) {
        self.pinningPolicies = pinning
        self.logger = logger
        self.testAnchors = nil
    }

    /// Test-only initializer: trust exactly `testAnchors` instead of the system roots.
    init(pinning: [PinningPolicy], logger: (any SecurityEventLogger)?, testAnchors: [Certificate]) {
        self.pinningPolicies = pinning
        self.logger = logger
        self.testAnchors = testAnchors
    }

    /// Evaluates `chain` for `host`. Runs off the main actor (nonisolated `async`) since `SecTrust`
    /// may perform revocation I/O.
    public func evaluate(
        _ chain: CertificateChain, for host: String
    ) async throws(CertificateError) -> EvaluatedCertificateChain {
        guard let leaf = chain.certificates.first else {
            throw CertificateError.malformedEncoding(detail: .notACertificate)
        }

        // The presented chain, plus any test anchors so SecTrust can complete the chain to them.
        // Pin comparison below still uses only `chain.certificates` (the presented chain).
        var secCertificates: [SecCertificate] = []
        for certificate in chain.certificates + (testAnchors ?? []) {
            guard let sec = SecCertificateCreateWithData(nil, certificate.derRepresentation as CFData) else {
                throw CertificateError.malformedEncoding(detail: .notACertificate)
            }
            secCertificates.append(sec)
        }

        let policy = SecPolicyCreateSSL(true, host as CFString)
        var trust: SecTrust?
        let createStatus = SecTrustCreateWithCertificates(secCertificates as CFArray, policy, &trust)
        guard createStatus == errSecSuccess, let trust else {
            throw CertificateError.systemTrustFailed(underlying: createStatus, host: host)
        }

        if let testAnchors {
            let anchors = testAnchors.compactMap { SecCertificateCreateWithData(nil, $0.derRepresentation as CFData) }
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
        }

        // System trust ALWAYS first.
        var trustError: CFError?
        guard SecTrustEvaluateWithError(trust, &trustError) else {
            let code = trustError.map { CFErrorGetCode($0) } ?? -1
            throw CertificateError.systemTrustFailed(underlying: OSStatus(truncatingIfNeeded: code), host: host)
        }

        // Pins are additive over system trust.
        let applicable = pinningPolicies.filter { $0.governs(host: host) }
        guard !applicable.isEmpty else {
            return EvaluatedCertificateChain(leaf: leaf, host: host, evaluatedAt: Date(), matchedPin: nil)
        }

        let now = Date()
        for policy in applicable {
            if case .enforceUntil(let deadline) = policy.expiry, let deadline, deadline < now {
                logger?.log(.pinningFailure(host: host))
                throw CertificateError.pinSetExpired(host: host, expiredAt: deadline)
            }
        }

        let presented = Set(chain.certificates.map { SPKIHash(of: $0) })
        for policy in applicable {
            if let matched = policy.acceptablePins.first(where: { presented.contains($0) }) {
                return EvaluatedCertificateChain(leaf: leaf, host: host, evaluatedAt: Date(), matchedPin: matched)
            }
        }

        logger?.log(.pinningFailure(host: host))
        throw CertificateError.pinMismatch(host: host)
    }
}
