/// A seam for evaluating server trust (certificate pinning / chain validation).
///
/// Conformed to by `BolourCertificates.TrustEvaluator` and consumed by `BolourNetworkSecurity`.
/// The concrete evaluation surface is added when those modules land; Core owns only the seam
/// so the layers stay independently importable and testable.
public protocol TrustEvaluating: Sendable {}
