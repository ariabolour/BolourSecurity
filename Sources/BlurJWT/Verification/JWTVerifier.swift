import Foundation

/// Verifies a `UnverifiedJWT` into a `VerifiedJWT<Claims>` — the only path claims are reachable
/// through.
public struct JWTVerifier: Sendable {
    private let keySource: JWTKeySource
    private let policy: JWTValidationPolicy

    /// Keys carry their own algorithm, so the allowlist is derived from the keys — never from
    /// the token's header.
    public init(keys: some Collection<any JWTVerificationKey>, policy: JWTValidationPolicy) {
        self.keySource = .fixed(Array(keys))
        self.policy = policy
    }

    public init(jwks: some JWKSProviding, policy: JWTValidationPolicy) {
        self.keySource = .jwks(jwks)
        self.policy = policy
    }

    public func verify<C: JWTClaims>(
        _ token: UnverifiedJWT, as claimsType: C.Type = RegisteredClaims.self
    ) async throws(JWTError) -> VerifiedJWT<C> {
        let keys = try await resolveKeys()

        // kid, when present, narrows candidates; it never substitutes for checking the signature.
        let candidates: [any JWTVerificationKey]
        if let keyID = token.unverifiedHeader.keyID {
            let matching = keys.filter { $0.keyID == keyID }
            guard !matching.isEmpty else { throw JWTError.unknownKeyID(keyID) }
            candidates = matching
        } else {
            candidates = keys
        }

        // The header's alg is checked for *consistency* against the candidate keys' own
        // algorithms — it never selects which verification routine runs.
        let algorithmMatched = candidates.filter { $0.jwtAlgorithm == token.unverifiedHeader.algorithm }
        guard !algorithmMatched.isEmpty else {
            throw JWTError.algorithmMismatch(tokenAlgorithm: token.unverifiedHeader.algorithm)
        }
        guard algorithmMatched.contains(where: { $0.isValidSignature(token.signature, signingInput: token.signingInput) }) else {
            throw JWTError.signatureInvalid
        }

        let registered: RegisteredClaims
        let claims: C
        do {
            let decoder = ClaimsCoding.makeDecoder()
            registered = try decoder.decode(RegisteredClaims.self, from: token.decodedPayload)
            claims = try decoder.decode(claimsType, from: token.decodedPayload)
        } catch {
            throw JWTError.claimsDecodingFailed(underlying: error)
        }

        let now = Date()
        let skew = policy.clockSkewTolerance.timeInterval

        if let expiresAt = registered.expiresAt {
            guard expiresAt.addingTimeInterval(skew) > now else { throw JWTError.expired(at: expiresAt) }
        } else if policy.requireExpiry {
            // No exp claim at all, but the policy requires one: treated as unconditionally
            // expired (the fail-closed reading) rather than inventing a new error case for
            // "missing a required claim" outside the design's given error set.
            throw JWTError.expired(at: .distantPast)
        }

        if let notBefore = registered.notBefore {
            guard notBefore.addingTimeInterval(-skew) <= now else { throw JWTError.notYetValid(until: notBefore) }
        }

        guard registered.issuer == policy.issuer else {
            throw JWTError.issuerMismatch(expected: policy.issuer)
        }
        guard let audience = registered.audience, audience.contains(policy.audience) else {
            throw JWTError.audienceMismatch(expected: policy.audience)
        }

        return VerifiedJWT(claims: claims, registered: registered, verifiedAt: now)
    }

    private func resolveKeys() async throws(JWTError) -> [any JWTVerificationKey] {
        switch keySource {
        case .fixed(let keys):
            return keys
        case .jwks(let provider):
            do { return try await provider.currentKeys() }
            catch { throw JWTError.jwksUnavailable(underlying: error) }
        }
    }
}

enum JWTKeySource: Sendable {
    case fixed([any JWTVerificationKey])
    case jwks(any JWKSProviding)
}

extension Duration {
    var timeInterval: TimeInterval {
        let components = self.components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1e18
    }
}
