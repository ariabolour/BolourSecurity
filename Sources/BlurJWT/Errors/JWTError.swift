import Foundation
import BlurSecurityCore

/// Where compact-serialization parsing rejected an input. Carries no attacker-useful detail
/// beyond a category.
public enum MalformationDetail: Sendable, Hashable, CustomStringConvertible {
    case wrongSegmentCount(Int)
    case segmentTooLarge
    case invalidBase64
    case headerNotJSON
    case headerMissingAlgorithm

    public var description: String {
        switch self {
        case .wrongSegmentCount(let count): return "expected 3 segments, found \(count)"
        case .segmentTooLarge: return "a segment exceeded the size limit"
        case .invalidBase64: return "invalid base64url"
        case .headerNotJSON: return "header was not a JSON object"
        case .headerMissingAlgorithm: return "header is missing \"alg\""
        }
    }
}

/// The closed failure domain of `BlurJWT`.
///
/// `issuerMismatch`/`audienceMismatch` intentionally omit the token's presented value — the
/// expected value alone is enough to act on, and echoing attacker-controlled token content back
/// into logs is a habit this ecosystem doesn't want to normalize.
public enum JWTError: SecurityError {
    case malformedToken(detail: MalformationDetail)
    case signatureInvalid
    /// The token's header named an algorithm none of the verifier's keys support. The header's
    /// `alg` is only ever checked for *consistency* with the key that matches its `kid` (or, with
    /// no `kid`, any key of a compatible algorithm) — it never selects the algorithm itself.
    case algorithmMismatch(tokenAlgorithm: String)
    case expired(at: Date)
    case notYetValid(until: Date)
    case issuerMismatch(expected: String)
    case audienceMismatch(expected: String)
    case unknownKeyID(String)
    case claimsDecodingFailed(underlying: any Error & Sendable)
    case jwksUnavailable(underlying: any Error & Sendable)
    /// `JWTSigner.sign` failed at the underlying cryptographic operation. Not part of the
    /// design's original verification-side error set, but `sign` needs a way to report failure
    /// and none of the verification cases fit — added the same way `BlurNetworkSecurity`'s
    /// `SecurityEvent.Kind` and other closed sets here have grown deliberately as gaps surface.
    case signingFailed(underlying: any Error & Sendable)

    public var failureIsRecoverable: Bool {
        switch self {
        case .expired, .notYetValid, .unknownKeyID, .jwksUnavailable:
            return true
        case .malformedToken, .signatureInvalid, .algorithmMismatch, .issuerMismatch,
             .audienceMismatch, .claimsDecodingFailed, .signingFailed:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .malformedToken(let detail):
            return "The token's compact serialization was malformed (\(detail))."
        case .signatureInvalid:
            return "The signature did not verify."
        case .algorithmMismatch(let tokenAlgorithm):
            return "The token's header names algorithm “\(tokenAlgorithm)”, which none of the verifier's keys support."
        case .expired(let at):
            return "The token expired at \(at)."
        case .notYetValid(let until):
            return "The token is not valid until \(until)."
        case .issuerMismatch(let expected):
            return "The token's issuer does not match the expected issuer “\(expected)”."
        case .audienceMismatch(let expected):
            return "The token's audience does not include the expected audience “\(expected)”."
        case .unknownKeyID(let kid):
            return "No key matches the token's key ID “\(kid)”."
        case .claimsDecodingFailed(let underlying):
            return "The token's claims could not be decoded: \(underlying)."
        case .jwksUnavailable(let underlying):
            return "The JWK Set could not be fetched: \(underlying)."
        case .signingFailed(let underlying):
            return "Signing failed: \(underlying)."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .malformedToken, .signatureInvalid, .algorithmMismatch, .issuerMismatch, .audienceMismatch:
            return nil
        case .expired:
            return "Refresh the token; if this recurs immediately after issuance, check for clock drift."
        case .notYetValid:
            return "Check for clock drift between the issuer and this device."
        case .unknownKeyID:
            return "Refresh the JWK Set (key rotation) before treating this as a hard failure."
        case .claimsDecodingFailed:
            return "Confirm the claims type matches what the issuer actually sends."
        case .jwksUnavailable:
            return "Retry; if it persists, confirm network access and the JWKS URL."
        case .signingFailed:
            return "Retry; if it persists, confirm the signing key is still valid."
        }
    }

    public var debugDescription: String {
        "JWTError(\(errorDescription ?? "unknown"))"
    }
}
