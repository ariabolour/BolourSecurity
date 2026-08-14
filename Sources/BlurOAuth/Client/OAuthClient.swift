import Foundation
import AuthenticationServices
import BlurSecurityCore
import BlurJWT

/// Authorization Code + PKCE through `ASWebAuthenticationSession`, ID-token verification (when
/// OIDC) through `BlurJWT`, token custody through the `SecretStore` seam.
public struct OAuthClient: Sendable {
    private let configuration: OAuthConfiguration
    private let tokenStore: any SecretStore
    private let session: URLSession
    private let logger: (any SecurityEventLogger)?
    private let authorizationPresenter: any AuthorizationSessionPresenting

    private static let tokenItemKey: ItemKey = "blur.oauth.tokens"

    public init(
        configuration: OAuthConfiguration, tokenStore: some SecretStore,
        session: URLSession = .shared, logger: (any SecurityEventLogger)? = nil
    ) {
        self.init(
            configuration: configuration, tokenStore: tokenStore, session: session, logger: logger,
            authorizationPresenter: RealAuthorizationSession()
        )
    }

    /// Test-only: substitutes a scripted `AuthorizationSessionPresenting` double for the real
    /// `ASWebAuthenticationSession`.
    init(
        configuration: OAuthConfiguration, tokenStore: any SecretStore, session: URLSession,
        logger: (any SecurityEventLogger)?, authorizationPresenter: any AuthorizationSessionPresenting
    ) {
        self.configuration = configuration
        self.tokenStore = tokenStore
        self.session = session
        self.logger = logger
        self.authorizationPresenter = authorizationPresenter
    }

    /// The whole dance: PKCE pair, state, web session, code exchange, ID-token verification
    /// (when OIDC), token custody. Returns a live session.
    @MainActor
    public func signIn(
        presentingFrom anchor: ASPresentationAnchor, prefersEphemeralSession: Bool = false
    ) async throws(OAuthError) -> OAuthSession {
        let endpoints = try await configuration.resolveEndpoints(session: session)
        let pkce = PKCEPair.generate()
        let state = AttemptToken.generate()
        let nonce = configuration.isOIDC ? AttemptToken.generate() : nil

        let authorizationURL = try buildAuthorizationURL(endpoints: endpoints, pkce: pkce, state: state, nonce: nonce)

        let callbackURL = try await authorizationPresenter.present(
            url: authorizationURL,
            callbackURLScheme: configuration.redirectURI.scheme ?? "",
            prefersEphemeralSession: prefersEphemeralSession,
            anchor: anchor
        )

        let code = try extractCode(from: callbackURL, expectedState: state)
        let tokenResponse = try await exchangeCode(code, verifier: pkce.verifier, endpoints: endpoints)
        let user = try await verifyIDTokenIfPresent(in: tokenResponse, endpoints: endpoints, nonce: nonce)

        let tokenManager = TokenManager(
            tokenStore: tokenStore, itemKey: OAuthClient.tokenItemKey, tokenEndpoint: endpoints.token,
            revocationEndpoint: endpoints.revocation, clientID: configuration.clientID, session: session, logger: logger
        )
        let storedSet = StoredTokenSet(
            accessToken: tokenResponse.accessToken, refreshToken: tokenResponse.refreshToken,
            expiresAt: tokenResponse.expiresIn.map { Date().addingTimeInterval($0) },
            tokenType: tokenResponse.tokenType, scope: tokenResponse.scope
        )
        try await tokenManager.persist(storedSet)

        return OAuthSession(user: user, tokens: tokenManager)
    }

    /// App-to-service (no user). Separate entry point; separate mental model.
    public func clientCredentialsToken() async throws(OAuthError) -> AccessToken {
        let endpoints = try await configuration.resolveEndpoints(session: session)
        var request = URLRequest(url: endpoints.token)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(FormEncoding.encode([
            "grant_type": "client_credentials", "client_id": configuration.clientID,
            "scope": configuration.scopes.spaceSeparated,
        ]).utf8)

        let data: Data
        let response: URLResponse
        do { (data, response) = try await session.data(for: request) }
        catch { throw OAuthError.codeExchangeFailed(statusCode: nil, providerError: nil) }

        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let status = (response as? HTTPURLResponse)?.statusCode
            let providerError = (try? JSONDecoder().decode(TokenEndpointErrorResponse.self, from: data))
                .flatMap { ProviderErrorCode(rawValue: $0.error) }
            throw OAuthError.codeExchangeFailed(statusCode: status, providerError: providerError)
        }

        do {
            let tokenResponse = try JSONDecoder().decode(TokenEndpointResponse.self, from: data)
            return AccessToken(
                value: tokenResponse.accessToken,
                expiresAt: tokenResponse.expiresIn.map { Date().addingTimeInterval($0) }
            )
        } catch {
            throw OAuthError.codeExchangeFailed(statusCode: nil, providerError: nil)
        }
    }

    // MARK: - Internals

    private func buildAuthorizationURL(
        endpoints: ResolvedEndpoints, pkce: PKCEPair, state: String, nonce: String?
    ) throws(OAuthError) -> URL {
        guard var components = URLComponents(url: endpoints.authorization, resolvingAgainstBaseURL: false) else {
            throw OAuthError.providerMisconfigured(detail: .incompleteDiscoveryDocument)
        }
        var items = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: configuration.scopes.spaceSeparated),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: pkce.challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]
        if let nonce { items.append(URLQueryItem(name: "nonce", value: nonce)) }
        components.queryItems = (components.queryItems ?? []) + items
        guard let url = components.url else {
            throw OAuthError.providerMisconfigured(detail: .incompleteDiscoveryDocument)
        }
        return url
    }

    private func extractCode(from callbackURL: URL, expectedState: String) throws(OAuthError) -> String {
        let items = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
        guard items.first(where: { $0.name == "state" })?.value == expectedState else {
            throw OAuthError.stateMismatch
        }
        if let code = items.first(where: { $0.name == "code" })?.value {
            return code
        }
        let providerErrorRaw = items.first(where: { $0.name == "error" })?.value
        throw OAuthError.codeExchangeFailed(
            statusCode: nil, providerError: providerErrorRaw.flatMap(ProviderErrorCode.init(rawValue:))
        )
    }

    private func exchangeCode(
        _ code: String, verifier: String, endpoints: ResolvedEndpoints
    ) async throws(OAuthError) -> TokenEndpointResponse {
        var request = URLRequest(url: endpoints.token)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(FormEncoding.encode([
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": configuration.redirectURI.absoluteString,
            "client_id": configuration.clientID, "code_verifier": verifier,
        ]).utf8)

        let data: Data
        let response: URLResponse
        do { (data, response) = try await session.data(for: request) }
        catch { throw OAuthError.codeExchangeFailed(statusCode: nil, providerError: nil) }

        guard let http = response as? HTTPURLResponse else {
            throw OAuthError.codeExchangeFailed(statusCode: nil, providerError: nil)
        }
        guard (200..<300).contains(http.statusCode) else {
            let providerError = (try? JSONDecoder().decode(TokenEndpointErrorResponse.self, from: data))
                .flatMap { ProviderErrorCode(rawValue: $0.error) }
            throw OAuthError.codeExchangeFailed(statusCode: http.statusCode, providerError: providerError)
        }
        do {
            return try JSONDecoder().decode(TokenEndpointResponse.self, from: data)
        } catch {
            throw OAuthError.codeExchangeFailed(statusCode: http.statusCode, providerError: nil)
        }
    }

    private func verifyIDTokenIfPresent(
        in tokenResponse: TokenEndpointResponse, endpoints: ResolvedEndpoints, nonce: String?
    ) async throws(OAuthError) -> VerifiedJWT<IDTokenClaims>? {
        guard configuration.isOIDC, let idToken = tokenResponse.idToken else { return nil }
        guard case .discovering(let issuer) = configuration.endpointSource, let jwksURI = endpoints.jwksURI else {
            throw OAuthError.providerMisconfigured(detail: .incompleteDiscoveryDocument)
        }

        let verifier = JWTVerifier(
            jwks: RemoteJWKSet(url: jwksURI, session: session),
            policy: JWTValidationPolicy(issuer: issuer.absoluteString, audience: configuration.clientID)
        )
        let verified: VerifiedJWT<IDTokenClaims>
        do {
            verified = try await verifier.verify(UnverifiedJWT(compactSerialization: idToken), as: IDTokenClaims.self)
        } catch {
            throw OAuthError.idTokenVerificationFailed(underlying: error)
        }
        guard verified.claims.nonce == nonce else {
            throw OAuthError.idTokenVerificationFailed(underlying: .signatureInvalid)
        }
        return verified
    }
}
