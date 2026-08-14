import Foundation
import BlurSecurityCore

/// Single-flight refresh: N concurrent callers, one network refresh, everyone gets the same
/// fresh token. One of the ecosystem's sanctioned actors — this is the module's hardest
/// correctness problem, which is why it lives behind actor isolation rather than a lock.
public actor TokenManager {
    private let tokenStore: any SecretStore
    private let itemKey: ItemKey
    private let tokenEndpoint: URL
    private let revocationEndpoint: URL?
    private let clientID: String
    private let session: URLSession
    private let logger: (any SecurityEventLogger)?

    private var refreshTask: Task<AccessToken, any Error>?
    private var isPoisoned = false
    private let invalidationContinuation: AsyncStream<SessionInvalidationReason>.Continuation
    /// `nonisolated`: matches the design's own usage (`for await reason in session.tokens.sessionInvalidated`
    /// with no `await` on the property access itself) — `AsyncStream` is Sendable and this `let`
    /// is never reassigned after `init`, so exposing it without hopping onto the actor is safe.
    public nonisolated let sessionInvalidated: AsyncStream<SessionInvalidationReason>

    init(
        tokenStore: any SecretStore, itemKey: ItemKey, tokenEndpoint: URL, revocationEndpoint: URL?,
        clientID: String, session: URLSession, logger: (any SecurityEventLogger)?
    ) {
        self.tokenStore = tokenStore
        self.itemKey = itemKey
        self.tokenEndpoint = tokenEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.clientID = clientID
        self.session = session
        self.logger = logger
        let stream = AsyncStream<SessionInvalidationReason>.makeStream()
        self.sessionInvalidated = stream.stream
        self.invalidationContinuation = stream.continuation
    }

    /// The only token accessor most apps ever need: returns a valid access token, transparently
    /// refreshing (with a 30-second leeway) when needed.
    public func validAccessToken() async throws(OAuthError) -> AccessToken {
        guard !isPoisoned else { throw OAuthError.sessionInvalidated(.noRefreshToken) }
        guard let stored = try await loadStoredTokens() else {
            throw OAuthError.sessionInvalidated(.noRefreshToken)
        }
        if let expiresAt = stored.expiresAt, expiresAt > Date().addingTimeInterval(30) {
            return AccessToken(value: stored.accessToken, expiresAt: stored.expiresAt)
        }
        return try await refreshNow()
    }

    public func refreshNow() async throws(OAuthError) -> AccessToken {
        guard !isPoisoned else { throw OAuthError.sessionInvalidated(.noRefreshToken) }

        if let refreshTask {
            return try await await_(refreshTask)
        }
        let task = Task<AccessToken, any Error> { try await self.performRefresh() }
        refreshTask = task
        defer { refreshTask = nil }
        return try await await_(task)
    }

    private func await_(_ task: Task<AccessToken, any Error>) async throws(OAuthError) -> AccessToken {
        do {
            return try await task.value
        } catch let error as OAuthError {
            throw error
        } catch {
            throw OAuthError.refreshFailed(underlying: error)
        }
    }

    /// Revokes (when the provider supports it) and destroys stored tokens. Fires
    /// `sessionInvalidated` exactly once, like any other poisoning path.
    public func signOut() async throws(OAuthError) {
        if let revocationEndpoint, let stored = try await loadStoredTokens(), let refreshToken = stored.refreshToken {
            try? await revoke(refreshToken, at: revocationEndpoint)
        }
        try? await clearStoredTokens()
        poison(reason: .noRefreshToken)
    }

    // MARK: - Refresh implementation

    private func performRefresh() async throws(OAuthError) -> AccessToken {
        guard let stored = try await loadStoredTokens(), let refreshToken = stored.refreshToken else {
            poison(reason: .noRefreshToken)
            throw OAuthError.sessionInvalidated(.noRefreshToken)
        }

        var request = URLRequest(url: tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(FormEncoding.encode([
            "grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": clientID,
        ]).utf8)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw OAuthError.refreshFailed(underlying: error)
        }

        guard let http = response as? HTTPURLResponse else {
            throw OAuthError.refreshFailed(underlying: URLError(.badServerResponse))
        }
        guard (200..<300).contains(http.statusCode) else {
            let providerError = (try? JSONDecoder().decode(TokenEndpointErrorResponse.self, from: data))
                .flatMap { ProviderErrorCode(rawValue: $0.error) }
            if providerError == .invalidGrant {
                // The token endpoint alone cannot distinguish "this refresh token was already
                // rotated out from under you" (reuse/theft) from a plain revocation — both are
                // invalid_grant. Either way, refreshing further with this token can never
                // succeed, so both poison the session identically; a server-side reuse-detection
                // signal, if the provider offers one, is a documented enhancement apps can layer
                // on, not something derivable from this response alone.
                try? await clearStoredTokens()
                poison(reason: .refreshTokenReuseDetected)
                throw OAuthError.sessionInvalidated(.refreshTokenReuseDetected)
            }
            throw OAuthError.codeExchangeFailed(statusCode: http.statusCode, providerError: providerError)
        }

        let tokenResponse: TokenEndpointResponse
        do {
            tokenResponse = try JSONDecoder().decode(TokenEndpointResponse.self, from: data)
        } catch {
            throw OAuthError.refreshFailed(underlying: error)
        }

        // Rotation: the new refresh token (when the provider issues one) atomically replaces
        // the old one in storage — there is no window where storage holds neither.
        let newSet = StoredTokenSet(
            accessToken: tokenResponse.accessToken,
            refreshToken: tokenResponse.refreshToken ?? refreshToken,
            expiresAt: tokenResponse.expiresIn.map { Date().addingTimeInterval($0) },
            tokenType: tokenResponse.tokenType, scope: tokenResponse.scope
        )
        try await persist(newSet)
        return AccessToken(value: newSet.accessToken, expiresAt: newSet.expiresAt)
    }

    private func revoke(_ token: String, at endpoint: URL) async throws {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(FormEncoding.encode(["token": token, "client_id": clientID]).utf8)
        _ = try await session.data(for: request)
    }

    private func poison(reason: SessionInvalidationReason) {
        guard !isPoisoned else { return }
        isPoisoned = true
        invalidationContinuation.yield(reason)
    }

    // MARK: - Storage

    func persist(_ set: StoredTokenSet) async throws(OAuthError) {
        do {
            try await tokenStore.store(try set.secureBytesRepresentation(), for: itemKey)
        } catch {
            throw OAuthError.refreshFailed(underlying: error)
        }
    }

    private func loadStoredTokens() async throws(OAuthError) -> StoredTokenSet? {
        do {
            guard let bytes = try await tokenStore.secret(for: itemKey) else { return nil }
            return try StoredTokenSet(secureBytes: bytes)
        } catch {
            throw OAuthError.refreshFailed(underlying: error)
        }
    }

    private func clearStoredTokens() async throws {
        try await tokenStore.removeSecret(for: itemKey)
    }
}

enum FormEncoding {
    static func encode(_ fields: [String: String]) -> String {
        fields.sorted { $0.key < $1.key }
            .map { key, value in
                "\(percentEncode(key))=\(percentEncode(value))"
            }
            .joined(separator: "&")
    }

    private static func percentEncode(_ string: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return string.addingPercentEncoding(withAllowedCharacters: allowed) ?? string
    }
}
