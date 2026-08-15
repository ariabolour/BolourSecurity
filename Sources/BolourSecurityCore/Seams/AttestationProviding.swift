/// A seam for producing app/device attestations.
///
/// Conformed to by `BolourAppIntegrity.AttestationService` and consumed by an app's networking
/// layer. As with ``TrustEvaluating``, Core owns only the seam; the concrete surface arrives
/// with `BolourAppIntegrity`.
public protocol AttestationProviding: Sendable {}
