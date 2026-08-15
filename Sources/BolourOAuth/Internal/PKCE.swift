import Foundation
import BolourCrypto

/// A PKCE (RFC 7636) verifier/challenge pair. Generated fresh per attempt via `SecureRandom` —
/// there is no API to disable PKCE, downgrade to `plain`, or supply a caller-provided verifier.
struct PKCEPair: Sendable {
    let verifier: String
    let challenge: String

    static func generate() -> PKCEPair {
        let verifier = OAuthBase64URL.encode(SecureRandom.data(count: 32))
        let challengeDigest = SHA256.digest(of: Data(verifier.utf8))
        let challenge = OAuthBase64URL.encode(challengeDigest.withUnsafeBytes { Data($0) })
        return PKCEPair(verifier: verifier, challenge: challenge)
    }
}

/// A fresh, unpredictable token for `state`/`nonce` — bound to one attempt, never reused.
enum AttemptToken {
    static func generate() -> String {
        OAuthBase64URL.encode(SecureRandom.data(count: 24))
    }
}

/// Unpadded base64url — its own copy rather than reaching into `BolourJWT`'s internal one (a
/// different module can't see it, and the encoding is a few lines either way).
enum OAuthBase64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
