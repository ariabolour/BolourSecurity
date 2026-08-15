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

        let configuration = OAuthConfiguration(
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

        let configuration = OAuthConfiguration.discovering(
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
        let configuration = OAuthConfiguration(
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
        let configuration = OAuthConfiguration(
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
        let configuration = OAuthConfiguration(
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
        let configuration = OAuthConfiguration(
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
        let configuration = OAuthConfiguration.discovering(
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
        let configuration = OAuthConfiguration.discovering(
            issuer: idp.issuer, clientID: "client-1", redirectURI: URL(string: "myapp://callback")!, scopes: .openID
        )
        _ = try await configuration.resolveEndpoints(session: makeSession())
    }
}
