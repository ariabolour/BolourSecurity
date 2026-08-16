import Testing
import Foundation
import AuthenticationServices
import BolourCrypto
@testable import BolourOAuth

@Suite("OAuthClient.signIn")
struct OAuthClientTests {

    private func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [LocalIdPProtocol.self]
        return URLSession(configuration: configuration)
    }

    @MainActor
    private func dummyAnchor() -> ASPresentationAnchor {
        #if os(macOS)
        return NSWindow()
        #else
        return UIWindow()
        #endif
    }

    @Test("non-OIDC happy path: explicit endpoints, tokens stored, no ID token")
    @MainActor
    func nonOIDCHappyPath() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .success(accessToken: "access-1", refreshToken: "refresh-1", expiresIn: 3600) }
        let presenter = FakeAuthorizationSessionPresenting()
        let store = FakeSecretStore()

        let configuration = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "\(idp.issuer)/authorize")!,
            tokenEndpoint: URL(string: "\(idp.issuer)/token")!,
            clientID: "client-1", redirectURI: URL(string: "myapp://callback")!,
            scopes: ["read"]
        )
        let client = OAuthClient(
            configuration: configuration, tokenStore: store, session: makeSession(),
            logger: nil, authorizationPresenter: presenter
        )

        let session = try await client.signIn(presentingFrom: dummyAnchor())
        #expect(session.user == nil)
        let token = try await session.tokens.validAccessToken()
        #expect(token.headerValue == "Bearer access-1")
    }

    @Test("OIDC happy path: discovery, ID token verified, nonce checked")
    @MainActor
    func oidcHappyPath() async throws {
        let idp = LocalIdP()
        let presenter = FakeAuthorizationSessionPresenting()
        presenter.idp = idp
        presenter.idTokenSubject = "user-42"
        idp.tokenEndpointHandler = { _ in .success(accessToken: "access-1", refreshToken: "refresh-1", expiresIn: 3600, idToken: idp.pendingIDToken) }
        let store = FakeSecretStore()

        let configuration = try OAuthConfiguration.discovering(
            issuer: idp.issuer, clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: .openID
        )
        let client = OAuthClient(
            configuration: configuration, tokenStore: store, session: makeSession(),
            logger: nil, authorizationPresenter: presenter
        )

        let session = try await client.signIn(presentingFrom: dummyAnchor())
        #expect(session.user?.claims.subject == "user-42")
    }

    @Test("PKCE: the code_verifier sent to the token endpoint hashes to the challenge sent to the authorization endpoint")
    @MainActor
    func pkceVerifierMatchesChallenge() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .success(accessToken: "access-1", refreshToken: nil, expiresIn: 3600) }
        let presenter = FakeAuthorizationSessionPresenting()
        let store = FakeSecretStore()
        let configuration = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "\(idp.issuer)/authorize")!,
            tokenEndpoint: URL(string: "\(idp.issuer)/token")!,
            clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: ["read"]
        )
        let client = OAuthClient(
            configuration: configuration, tokenStore: store, session: makeSession(),
            logger: nil, authorizationPresenter: presenter
        )
        _ = try await client.signIn(presentingFrom: dummyAnchor())

        let presentedChallenge = URLComponents(url: presenter.lastPresentedURL!, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == "code_challenge" })?.value
        let sentVerifier = idp.lastTokenForm?["code_verifier"]
        #expect(presentedChallenge != nil)
        #expect(sentVerifier != nil)

        let expectedChallenge = OAuthBase64URL.encode(SHA256.digest(of: Data(sentVerifier!.utf8)).withUnsafeBytes { Data($0) })
        #expect(presentedChallenge == expectedChallenge)
    }

    @Test("state mismatch is rejected")
    @MainActor
    func stateMismatchRejected() async throws {
        let idp = LocalIdP()
        let presenter = FakeAuthorizationSessionPresenting()
        presenter.stateOverride = "forged-state"
        let store = FakeSecretStore()
        let configuration = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "\(idp.issuer)/authorize")!,
            tokenEndpoint: URL(string: "\(idp.issuer)/token")!,
            clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: ["read"]
        )
        let client = OAuthClient(
            configuration: configuration, tokenStore: store, session: makeSession(),
            logger: nil, authorizationPresenter: presenter
        )
        do {
            _ = try await client.signIn(presentingFrom: dummyAnchor())
            Issue.record("expected stateMismatch")
        } catch OAuthError.stateMismatch {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("user cancellation surfaces as userCancelledSignIn, not a generic failure")
    @MainActor
    func userCancellation() async throws {
        let idp = LocalIdP()
        let presenter = FakeAuthorizationSessionPresenting()
        presenter.succeeds = false
        let store = FakeSecretStore()
        let configuration = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "\(idp.issuer)/authorize")!,
            tokenEndpoint: URL(string: "\(idp.issuer)/token")!,
            clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: ["read"]
        )
        let client = OAuthClient(
            configuration: configuration, tokenStore: store, session: makeSession(),
            logger: nil, authorizationPresenter: presenter
        )
        do {
            _ = try await client.signIn(presentingFrom: dummyAnchor())
            Issue.record("expected userCancelledSignIn")
        } catch OAuthError.userCancelledSignIn {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("a code-exchange failure surfaces the provider's error code")
    @MainActor
    func codeExchangeFailureSurfacesProviderError() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .error(status: 400, code: "invalid_grant") }
        let presenter = FakeAuthorizationSessionPresenting()
        let store = FakeSecretStore()
        let configuration = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "\(idp.issuer)/authorize")!,
            tokenEndpoint: URL(string: "\(idp.issuer)/token")!,
            clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: ["read"]
        )
        let client = OAuthClient(
            configuration: configuration, tokenStore: store, session: makeSession(),
            logger: nil, authorizationPresenter: presenter
        )
        do {
            _ = try await client.signIn(presentingFrom: dummyAnchor())
            Issue.record("expected codeExchangeFailed")
        } catch OAuthError.codeExchangeFailed(let status, let providerError) {
            #expect(status == 400)
            #expect(providerError == .invalidGrant)
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("discovery metadata whose endpoints don't share the issuer's host is refused (mix-up hygiene)")
    func mixUpAttackRefused() async throws {
        let idp = LocalIdP()
        idp.discoveryEndpointHostOverride = "attacker-\(UUID().uuidString)"
        let configuration = try OAuthConfiguration.discovering(
            issuer: idp.issuer, clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: .openID
        )
        do {
            _ = try await configuration.resolveEndpoints(session: makeSession())
            Issue.record("expected providerMisconfigured")
        } catch OAuthError.providerMisconfigured(.endpointHostMismatch(_)) {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("discovery metadata whose endpoints DO share the issuer's host resolves cleanly")
    func matchingHostResolves() async throws {
        let idp = LocalIdP()
        let configuration = try OAuthConfiguration.discovering(
            issuer: idp.issuer, clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: .openID
        )
        _ = try await configuration.resolveEndpoints(session: makeSession())
    }

    @Test("discovered endpoints are held to the same URL rules as explicit ones", arguments: [
        ("token_endpoint", MisconfigurationDetail.insecureEndpoint(role: .token)),
        ("authorization_endpoint", .insecureEndpoint(role: .authorization)),
        ("revocation_endpoint", .insecureEndpoint(role: .revocation)),
        ("jwks_uri", .insecureEndpoint(role: .jwks)),
    ])
    func discoveredEndpointsMustBeHTTPS(member: String, expected: MisconfigurationDetail) async throws {
        let idp = LocalIdP()
        // Same host, so the mix-up check passes and this reaches the scheme check.
        idp.discoveryOverrides = [member: "http://\(idp.host)/x"]
        let configuration = try OAuthConfiguration.discovering(
            issuer: idp.issuer, clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: .openID
        )
        do {
            _ = try await configuration.resolveEndpoints(session: makeSession())
            Issue.record("expected providerMisconfigured")
        } catch let OAuthError.providerMisconfigured(detail) {
            #expect(detail == expected)
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    /// RFC 8414 §3.3. Previously the document's `issuer` was decoded and never compared.
    @Test("a discovery document whose own issuer disagrees with the one queried is refused")
    func discoveredIssuerMustMatch() async throws {
        let idp = LocalIdP()
        idp.discoveryOverrides = ["issuer": "https://someone-else.example.com"]
        let configuration = try OAuthConfiguration.discovering(
            issuer: idp.issuer, clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: .openID
        )
        do {
            _ = try await configuration.resolveEndpoints(session: makeSession())
            Issue.record("expected providerMisconfigured")
        } catch OAuthError.providerMisconfigured(.discoveredIssuerMismatch) {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    /// A swallowed `jwks_uri` resurfaces much later as an unexplained ID-token failure.
    @Test("a present-but-unparseable optional endpoint is refused, not silently dropped")
    func unparseableOptionalEndpointRefused() async throws {
        let idp = LocalIdP()
        idp.discoveryOverrides = ["jwks_uri": "https://exa mple.com/jwks"]
        let configuration = try OAuthConfiguration.discovering(
            issuer: idp.issuer, clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: .openID
        )
        do {
            _ = try await configuration.resolveEndpoints(session: makeSession())
            Issue.record("expected providerMisconfigured")
        } catch let OAuthError.providerMisconfigured(detail) {
            #expect(detail == .malformedEndpoint(role: .jwks))
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("a callback on the app's scheme but the wrong path is refused before state is even read")
    @MainActor
    func callbackRedirectURIMismatch() async throws {
        let idp = LocalIdP()
        let presenter = FakeAuthorizationSessionPresenting()
        // Same scheme — which is all ASWebAuthenticationSession dispatches on — different path.
        presenter.callbackURLOverride = URL(string: "myapp://callback/elsewhere")!
        let store = FakeSecretStore()
        let configuration = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "\(idp.issuer)/authorize")!,
            tokenEndpoint: URL(string: "\(idp.issuer)/token")!,
            clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: ["read"]
        )
        let client = OAuthClient(
            configuration: configuration, tokenStore: store, session: makeSession(),
            logger: nil, authorizationPresenter: presenter
        )
        do {
            _ = try await client.signIn(presentingFrom: dummyAnchor())
            Issue.record("expected redirectURIMismatch")
        } catch OAuthError.redirectURIMismatch {
            // expected: the state here is genuine, so a state-first check would have passed it.
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("a callback carrying the registered redirect URI plus the response query is accepted")
    @MainActor
    func callbackRedirectURIMatches() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .success(accessToken: "access-1", refreshToken: nil, expiresIn: 3600) }
        let presenter = FakeAuthorizationSessionPresenting()
        presenter.callbackURLOverride = URL(string: "MyApp://Callback")!    // case differs, shape doesn't
        let store = FakeSecretStore()
        let configuration = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "\(idp.issuer)/authorize")!,
            tokenEndpoint: URL(string: "\(idp.issuer)/token")!,
            clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: ["read"]
        )
        let client = OAuthClient(
            configuration: configuration, tokenStore: store, session: makeSession(),
            logger: nil, authorizationPresenter: presenter
        )
        _ = try await client.signIn(presentingFrom: dummyAnchor())
    }
}

@Suite("OAuth endpoint URL validation")
struct EndpointValidationTests {

    private let redirect = URL(string: "myapp://callback")!
    private let https = URL(string: "https://idp.example.com/authorize")!

    private func misconfiguration(
        _ operation: () throws -> some Any, sourceLocation: SourceLocation = #_sourceLocation
    ) -> MisconfigurationDetail? {
        do {
            _ = try operation()
            Issue.record("expected the configuration to be rejected", sourceLocation: sourceLocation)
            return nil
        } catch let OAuthError.providerMisconfigured(detail) {
            return detail
        } catch {
            Issue.record("expected providerMisconfigured, got \(error)", sourceLocation: sourceLocation)
            return nil
        }
    }

    @Test("explicit endpoints must be https", arguments: [
        "http://idp.example.com/authorize",
        "ftp://idp.example.com/authorize",
        "local-idp://idp.example.com/authorize",
    ])
    func explicitEndpointsRequireHTTPS(raw: String) throws {
        let insecure = URL(string: raw)!
        #expect(misconfiguration {
            try OAuthConfiguration(
                authorizationEndpoint: insecure, tokenEndpoint: https,
                clientID: "c", redirectURI: redirect, scopes: ["read"]
            )
        } == .insecureEndpoint(role: .authorization))
        #expect(misconfiguration {
            try OAuthConfiguration(
                authorizationEndpoint: https, tokenEndpoint: insecure,
                clientID: "c", redirectURI: redirect, scopes: ["read"]
            )
        } == .insecureEndpoint(role: .token))
    }

    @Test("an https scheme in any casing is accepted")
    func schemeCasingIsIgnored() throws {
        _ = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "HTTPS://idp.example.com/authorize")!,
            tokenEndpoint: https, clientID: "c", redirectURI: redirect, scopes: ["read"]
        )
    }

    @Test("an optional revocation endpoint is held to the same rule")
    func revocationEndpointRequiresHTTPS() throws {
        #expect(misconfiguration {
            try OAuthConfiguration(
                authorizationEndpoint: https, tokenEndpoint: https, clientID: "c",
                redirectURI: redirect, scopes: ["read"],
                revocationEndpoint: URL(string: "http://idp.example.com/revoke")!
            )
        } == .insecureEndpoint(role: .revocation))
    }

    @Test("endpoints with no host, embedded credentials, or a fragment are refused", arguments: [
        "https:///authorize",
        "https://user:secret@idp.example.com/authorize",
        "https://idp.example.com/authorize#fragment",
    ])
    func malformedEndpointsRefused(raw: String) throws {
        #expect(misconfiguration {
            try OAuthConfiguration(
                authorizationEndpoint: URL(string: raw)!, tokenEndpoint: https,
                clientID: "c", redirectURI: redirect, scopes: ["read"]
            )
        } == .malformedEndpoint(role: .authorization))
    }

    @Test("the issuer must be https and carry no query")
    func issuerRules() throws {
        #expect(misconfiguration {
            try OAuthConfiguration.discovering(
                issuer: URL(string: "http://idp.example.com")!, clientID: "c",
                redirectURI: redirect, scopes: .openID
            )
        } == .insecureEndpoint(role: .issuer))
        #expect(misconfiguration {
            try OAuthConfiguration.discovering(
                issuer: URL(string: "https://idp.example.com?tenant=1")!, clientID: "c",
                redirectURI: redirect, scopes: .openID
            )
        } == .malformedEndpoint(role: .issuer))
    }

    @Test("a redirect URI may use the app's own scheme or https, never plain http")
    func redirectURISchemes() throws {
        for acceptable in ["myapp://callback", "com.example.app:/oauth", "https://app.example.com/callback"] {
            _ = try OAuthConfiguration(
                authorizationEndpoint: https, tokenEndpoint: https, clientID: "c",
                redirectURI: URL(string: acceptable)!, scopes: ["read"]
            )
        }
        // Loopback (RFC 8252 §7.3) included: ASWebAuthenticationSession dispatches by scheme, so
        // this module could never deliver a callback to it.
        for raw in ["http://app.example.com/callback", "http://127.0.0.1:8080/callback"] {
            #expect(misconfiguration {
                try OAuthConfiguration(
                    authorizationEndpoint: https, tokenEndpoint: https, clientID: "c",
                    redirectURI: URL(string: raw)!, scopes: ["read"]
                )
            } == .insecureEndpoint(role: .redirect))
        }
    }

    @Test("redirect URIs a browser would treat as code or file access are refused", arguments: [
        "javascript://callback", "data://callback", "file://callback", "about://callback",
    ])
    func redirectURISchemeDenylist(raw: String) throws {
        #expect(misconfiguration {
            try OAuthConfiguration(
                authorizationEndpoint: https, tokenEndpoint: https, clientID: "c",
                redirectURI: URL(string: raw)!, scopes: ["read"]
            )
        } == .malformedEndpoint(role: .redirect))
    }

    @Test("a redirect URI with a fragment is refused")
    func redirectURIFragment() throws {
        #expect(misconfiguration {
            try OAuthConfiguration(
                authorizationEndpoint: https, tokenEndpoint: https, clientID: "c",
                redirectURI: URL(string: "myapp://callback#fragment")!, scopes: ["read"]
            )
        } == .malformedEndpoint(role: .redirect))
    }
}
