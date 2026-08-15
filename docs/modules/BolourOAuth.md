# BolourOAuth

**Layer 4 · Identity.** OAuth 2.1 and OpenID Connect with the sharp edges filed off — and the deprecated flows simply absent.

## Mission

Take a developer from "we have an identity provider" to a correct, secure, refresh-managed sign-in in one screen of code: Authorization Code + PKCE through `ASWebAuthenticationSession`, ID-token verification through `BolourJWT`, token custody through `BolourSecureStorage`, and a single-flight refresh actor that ends the duplicated-refresh bug class. The flows OAuth 2.1 removed (implicit, password grant) have no spelling here at all.

## Responsibilities

- Authorization Code + PKCE (S256) flow via `ASWebAuthenticationSession`, including state validation and redirect handling.
- OIDC discovery (issuer metadata), ID-token verification (nonce, issuer, audience) via `BolourJWT`.
- Token lifecycle: custody (via `SecretStore` seam → `TokenStore`), expiry-aware access, single-flight refresh, refresh-token rotation handling, revocation, and sign-out.
- Typed scopes, typed configuration, typed errors that distinguish user cancellation from protocol failure.
- Client-credentials flow for app-to-service calls (no user), explicitly separated.

Out of scope: Sign in with Apple UI (Apple's `ASAuthorizationController` owns that; an article shows how the resulting tokens flow into `TokenManager`), enterprise SSO extensions, WS-Fed/SAML.

## Public API (signature-level design)

```swift
public struct OAuthConfiguration: Sendable {
    /// OIDC discovery: endpoints fetched and validated from the issuer.
    public static func discovering(
        issuer: URL, clientID: String, redirectURI: URL, scopes: ScopeSet
    ) -> OAuthConfiguration
    /// Explicit endpoints for non-OIDC providers.
    public init(authorizationEndpoint: URL, tokenEndpoint: URL,
                clientID: String, redirectURI: URL, scopes: ScopeSet,
                revocationEndpoint: URL? = nil)
    // No clientSecret parameter exists on public-client initializers: secrets in
    // app binaries are not a thing we help people do. Confidential-client config
    // exists only on the clientCredentials surface, documented for server-mediated use.
}

public struct ScopeSet: Sendable, Hashable, ExpressibleByArrayLiteral {
    public static let openID: ScopeSet                     // openid profile email building blocks
}

public struct OAuthClient: Sendable {
    public init(configuration: OAuthConfiguration,
                tokenStore: some SecretStore,              // TokenStore is the canonical conformer
                session: URLSession = .shared,             // pass a BolourNetworkSecurity pinned session
                logger: (any SecurityEventLogger)? = nil)

    /// The whole dance: PKCE pair, state, web session, code exchange, ID-token
    /// verification (when OIDC), token custody. Returns a live session.
    @MainActor
    public func signIn(
        presentingFrom anchor: ASPresentationAnchor,
        prefersEphemeralSession: Bool = false              // default favors SSO; decision documented
    ) async throws(OAuthError) -> OAuthSession

    /// App-to-service (no user). Separate entry point; separate mental model.
    public func clientCredentialsToken() async throws(OAuthError) -> AccessToken
}

public struct OAuthSession: Sendable {
    public var user: VerifiedJWT<IDTokenClaims>? { get }   // present iff OIDC
    public var tokens: TokenManager { get }
}

/// Single-flight refresh: N concurrent callers, one network refresh, everyone
/// gets the same fresh token. One of the ecosystem's three sanctioned actors.
public actor TokenManager {
    /// The only token accessor most apps ever need: returns a valid access token,
    /// transparently refreshing (and handling rotation) when needed.
    public func validAccessToken() async throws(OAuthError) -> AccessToken

    public func refreshNow() async throws(OAuthError) -> AccessToken
    /// Revokes (when the provider supports it) and destroys stored tokens.
    public func signOut() async throws(OAuthError)
    /// Fires when refresh becomes impossible (rotation reuse, revocation):
    /// the app's "route to sign-in" signal, delivered once, deduplicated.
    public var sessionInvalidated: AsyncStream<SessionInvalidationReason> { get }
}

public struct AccessToken: Sendable {
    public var headerValue: String { get }                 // "Bearer eyJ…" — ready for URLRequest
    public var expiresAt: Date? { get }
    // Raw token string is deliberately NOT a String property; headerValue and
    // SecureBytes access cover real uses without inviting string interpolation into logs.
}

public struct IDTokenClaims: JWTClaims { … }               // sub, email?, name?, nonce …

public enum OAuthError: SecurityError {
    case userCancelledSignIn                               // distinct: it's a choice, not a failure
    case discoveryFailed(issuer: URL, underlying: any Error & Sendable)
    case stateMismatch                                     // CSRF tripwire: fails loudly, docs explain
    case codeExchangeFailed(statusCode: Int?, providerError: ProviderErrorCode?)
    case idTokenVerificationFailed(underlying: JWTError)
    case refreshFailed(underlying: any Error & Sendable)
    case sessionInvalidated(SessionInvalidationReason)     // rotation reuse, revoked, expired grant
    case providerMisconfigured(detail: MisconfigurationDetail)  // e.g. issuer/endpoint host mismatch
}
```

## Dependencies

`BolourSecurityCore`, `BolourJWT`, `BolourSecureStorage` (canonical store), `BolourNetworkSecurity` (recommended session); Apple: AuthenticationServices, Foundation.

## Architecture

- **PKCE is not a feature; it's the floor.** The verifier/challenge pair (S256) is generated internally per attempt via `SecureRandom`; there is no API to disable it, downgrade to `plain`, or supply your own. Likewise `state`: generated, bound to the attempt, validated on return — `stateMismatch` is a typed error because auditors ask for exactly this control.
- `signIn` is `@MainActor` because presentation is; everything after the redirect hops off. The `ASWebAuthenticationSession` delegate/anchor plumbing is fully internal.
- `TokenManager` owns the refresh state machine: expiry-with-leeway check → single-flight refresh → rotation handling (new refresh token atomically replaces old in the store *before* the old one's revocation window matters) → on `invalid_grant`-class outcomes, emits `sessionInvalidated` exactly once and poisons further calls with the same typed error. Concurrency here is the module's hardest correctness problem, which is why it's an actor and why its tests are the deepest.
- Discovery validates that token/authorization endpoints share the issuer's host (mix-up attack hygiene) and pins the metadata for the client's lifetime.
- ID-token verification reuses `BolourJWT` end to end: nonce from the attempt, issuer from discovery, audience = clientID. No second JWT implementation exists.

## Usage Examples

```swift
import BolourOAuth

let client = OAuthClient(
    configuration: .discovering(issuer: URL(string: "https://auth.example.com")!,
                                clientID: "com.example.app",
                                redirectURI: URL(string: "com.example.app:/callback")!,
                                scopes: .openID + ["offline_access"]),
    tokenStore: TokenStore(),
    session: .secure(policy: networkPolicy)
)

// Sign in (SwiftUI: anchor from @Environment)
let session = try await client.signIn(presentingFrom: anchor)
print("Hello \(session.user?.claims.name ?? "there")")

// Every API call thereafter — the only line most of the app ever sees:
var request = URLRequest(url: apiURL)
request.setValue(try await session.tokens.validAccessToken().headerValue,
                 forHTTPHeaderField: "Authorization")

// React to forced sign-out
for await reason in session.tokens.sessionInvalidated { showSignIn(reason) }
```

## Testing Strategy

- **Local IdP harness:** integration tests run against an in-process HTTP server implementing the code-exchange/refresh/revocation endpoints with scripted behaviors (happy path, rotation, `invalid_grant`, slow responses, malformed metadata). `ASWebAuthenticationSession` sits behind an internal seam so the authorization leg is scripted in unit tests; a UI-test lane on device CI exercises the real web session against the harness.
- **Refresh-storm suites (the crown jewels):** 100 concurrent `validAccessToken()` calls ⇒ exactly one refresh request observed; rotation mid-storm ⇒ zero uses of the retired refresh token; provider-side reuse detection simulation ⇒ exactly one `sessionInvalidated` emission and typed poisoning of subsequent calls.
- Protocol-conformance tests: PKCE pair correctness (RFC 7636 vectors), state round-trip, mix-up-attack fixtures (mismatched-host metadata ⇒ `providerMisconfigured`).
- Interop matrix (nightly): recorded fixture behaviors modeled on major IdPs' quirks (Auth0/Okta/Azure AD/Keycloak-shaped responses) — fixtures, not live services, so CI is hermetic.

## Security Considerations & Common Mistakes Prevented

- **Prevented: deprecated flows** — implicit and password grants are unrepresentable; PKCE and state are non-optional.
- **Prevented: client secrets in app binaries** — public-client configuration has no secret parameter; the docs explain the server-mediated pattern instead.
- **Prevented: duplicated refresh & rotation self-DoS** — single-flight actor semantics; rotation handled atomically with custody.
- **Prevented: tokens in logs** — `AccessToken` has no raw `String` surface; `headerValue` + redacted descriptions close the interpolation path.
- **Prevented: unverified ID tokens** — the only path to `user` runs through `BolourJWT` with nonce/issuer/audience enforced.
- **Honest limits:** custom-scheme redirects can be claimed by other apps on some OS versions — docs recommend Universal-Link redirects where the provider supports them and explain the residual risk; ephemeral vs. SSO session trade-offs are documented rather than decided silently.

## Future Roadmap

- DPoP (RFC 9449) sender-constrained tokens via `SecureEnclaveKey` + BolourJWT (v2.x — the flagship "better than bearer" story).
- Pushed Authorization Requests (PAR) and JARM as provider support matures (v2.x).
- Token-exchange (RFC 8693) for multi-audience architectures (v3.x).
- Passkey-first sign-in composition article with AuthenticationServices (v2.x, docs-first).
