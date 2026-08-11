/// A seam for producing app/device attestations.
///
/// Conformed to by `BlurAppIntegrity.AttestationService` and consumed by an app's networking
/// layer. As with ``TrustEvaluating``, Core owns only the seam; the concrete surface arrives
/// with `BlurAppIntegrity`.
public protocol AttestationProviding: Sendable {}
