/// A seam for evaluating server trust (certificate pinning / chain validation).
///
/// Conformed to by `BlurCertificates.TrustEvaluator` and consumed by `BlurNetworkSecurity`.
/// The concrete evaluation surface is added when those modules land; Core owns only the seam
/// so the layers stay independently importable and testable.
public protocol TrustEvaluating: Sendable {}
