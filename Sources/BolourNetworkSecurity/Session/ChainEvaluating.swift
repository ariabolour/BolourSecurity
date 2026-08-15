import BolourCertificates

/// An internal seam around `BolourCertificates.TrustEvaluator.evaluate`, so
/// ``SecureSessionDelegate`` can be constructed against a fault-injected double in tests
/// (throws, hangs, returns a chain that shouldn't have validated) without needing a live
/// TLS connection for every fail-closed assertion.
///
/// This is deliberately *not* the Core `TrustEvaluating` seam: that marker protocol carries no
/// requirements, because Core (Layer 0) cannot reference `CertificateChain`/`CertificateError`
/// without depending upward on `BolourCertificates` (Layer 2). `BolourNetworkSecurity` already
/// depends on `BolourCertificates` directly, so this seam lives here instead.
protocol ChainEvaluating: Sendable {
    func evaluate(
        _ chain: CertificateChain, for host: String
    ) async throws(CertificateError) -> EvaluatedCertificateChain
}

extension TrustEvaluator: ChainEvaluating {}
