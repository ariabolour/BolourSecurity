import Foundation

/// What a verified token must satisfy, beyond a valid signature.
public struct JWTValidationPolicy: Sendable {
    let issuer: String
    let audience: String
    let clockSkewTolerance: Duration
    let requireExpiry: Bool

    /// `clockSkewTolerance` beyond this is clamped, never honored — "disable time validation"
    /// has no spelling here. The temptation to widen leeway to paper over server clock drift
    /// hits this wall; the correct remedy is fixing the clock, not the policy.
    static let maximumClockSkewTolerance: Duration = .seconds(300)

    /// Issuer and audience are required: the two checks most hand-rolled verifiers skip are the
    /// two you cannot skip here.
    public init(
        issuer: String, audience: String,
        clockSkewTolerance: Duration = .seconds(60), requireExpiry: Bool = true
    ) {
        self.issuer = issuer
        self.audience = audience
        self.clockSkewTolerance = min(clockSkewTolerance, JWTValidationPolicy.maximumClockSkewTolerance)
        self.requireExpiry = requireExpiry
    }
}
