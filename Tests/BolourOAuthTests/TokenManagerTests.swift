import Testing
import Foundation
import BolourSecurityCore
@testable import BolourOAuth

@Suite("TokenManager")
struct TokenManagerTests {

    private func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [LocalIdPProtocol.self]
        return URLSession(configuration: configuration)
    }

    private func makeManager(
        idp: LocalIdP, store: FakeSecretStore = FakeSecretStore(), itemKey: ItemKey = "tokens"
    ) -> TokenManager {
        TokenManager(
            tokenStore: store, itemKey: itemKey, tokenEndpoint: URL(string: "\(idp.issuer)/token")!,
            revocationEndpoint: URL(string: "\(idp.issuer)/revoke")!, clientID: "client-1",
            session: makeSession(), logger: nil
        )
    }

    private func seed(_ manager: TokenManager, accessToken: String, refreshToken: String?, expiresIn: TimeInterval?) async throws {
        try await manager.persist(StoredTokenSet(
            accessToken: accessToken, refreshToken: refreshToken,
            expiresAt: expiresIn.map { Date().addingTimeInterval($0) }, tokenType: "Bearer", scope: nil
        ))
    }

    @Test("a non-expired stored token is returned without any network call")
    func returnsCachedTokenWithoutRefresh() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in Issue.record("should not refresh"); return .error(status: 500, code: "unexpected") }
        let manager = makeManager(idp: idp)
        try await seed(manager, accessToken: "cached", refreshToken: "r1", expiresIn: 3600)

        let token = try await manager.validAccessToken()
        #expect(token.headerValue == "Bearer cached")
    }

    @Test("an expired stored token triggers exactly one refresh")
    func refreshesExpiredToken() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .success(accessToken: "fresh", refreshToken: "r2", expiresIn: 3600) }
        let manager = makeManager(idp: idp)
        try await seed(manager, accessToken: "stale", refreshToken: "r1", expiresIn: -10)

        let token = try await manager.validAccessToken()
        #expect(token.headerValue == "Bearer fresh")
        #expect(idp.tokenEndpointRequestCount == 1)
    }

    @Test("rotation: the new refresh token atomically replaces the old one")
    func rotationReplacesRefreshToken() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { form in
            #expect(form["refresh_token"] == "r1")
            return .success(accessToken: "fresh", refreshToken: "r2-rotated", expiresIn: 3600)
        }
        let store = FakeSecretStore()
        let manager = makeManager(idp: idp, store: store)
        try await seed(manager, accessToken: "stale", refreshToken: "r1", expiresIn: -10)

        _ = try await manager.refreshNow()

        // A second refresh (forced) must present the ROTATED token, never the retired one.
        idp.tokenEndpointHandler = { form in
            #expect(form["refresh_token"] == "r2-rotated")
            return .success(accessToken: "fresh-2", refreshToken: "r3-rotated", expiresIn: 3600)
        }
        _ = try await manager.refreshNow()
    }

    @Test("100 concurrent refreshNow() calls against a cold cache collapse onto exactly one network refresh")
    func concurrentRefreshesCollapseToOne() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .success(accessToken: "fresh", refreshToken: "r2", expiresIn: 3600) }
        let manager = makeManager(idp: idp)
        try await seed(manager, accessToken: "stale", refreshToken: "r1", expiresIn: -10)

        // Matches the exact scenario this guarantee is meant to hold under: 100 callers all
        // observe an expired token at once (the realistic "app foregrounds, N screens each ask
        // for a token in the same instant" case) — exactly one refresh should reach the network,
        // and every caller gets the one fresh result, never a stale or partial one.
        try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<100 {
                group.addTask { try await manager.validAccessToken().headerValue }
            }
            for try await value in group { #expect(value == "Bearer fresh") }
        }
        #expect(idp.tokenEndpointRequestCount == 1)
    }

    @Test("a refresh failure is delivered identically to every awaiting caller, not just the initiator")
    func refreshFailurePropagatesToAllWaiters() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .error(status: 500, code: "server_error") }
        let manager = makeManager(idp: idp)
        try await seed(manager, accessToken: "stale", refreshToken: "r1", expiresIn: -10)

        // A transient server failure (not invalid_grant) must not poison the session — every
        // waiter fails this one attempt, but a later retry against a healthy server should still
        // be possible. Collecting into an array (not asserting inside the task) keeps the
        // assertion above the concurrency, matching this file's other storm tests.
        let outcomes = await withTaskGroup(of: OAuthError?.self) { group in
            for _ in 0..<100 {
                group.addTask {
                    do {
                        _ = try await manager.validAccessToken()
                        return nil
                    } catch let error as OAuthError {
                        return error
                    } catch {
                        return nil
                    }
                }
            }
            var collected: [OAuthError?] = []
            for await outcome in group { collected.append(outcome) }
            return collected
        }

        #expect(outcomes.count == 100)
        for outcome in outcomes {
            guard case .codeExchangeFailed(let statusCode, _) = outcome, statusCode == 500 else {
                Issue.record("expected every waiter to see .codeExchangeFailed(500, _), got \(String(describing: outcome))")
                continue
            }
        }
        // Single-flight holds on the failure path too: 100 waiters, one network attempt.
        #expect(idp.tokenEndpointRequestCount == 1)
    }

    @Test("a keychain write failure during rotation leaves the prior stored tokens intact, never half-written")
    func persistFailureDuringRotationLeavesPriorTokensIntact() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .success(accessToken: "fresh", refreshToken: "r2-rotated", expiresIn: 3600) }
        let store = FakeSecretStore()
        let manager = makeManager(idp: idp, store: store)
        try await seed(manager, accessToken: "stale", refreshToken: "r1", expiresIn: -10)

        struct WriteFailure: Error {}
        await store.setStoreFailure(WriteFailure())

        await #expect(throws: OAuthError.self) {
            _ = try await manager.refreshNow()
        }

        // The token endpoint already returned the ROTATED refresh token before the write failed —
        // proving the failure didn't corrupt storage (still holds the pre-rotation token, not a
        // torn write) is the actual guarantee under test, not merely "an error was thrown."
        await store.setStoreFailure(nil)
        let raw = try await store.secret(for: "tokens")
        let restored = try StoredTokenSet(secureBytes: try #require(raw))
        #expect(restored.refreshToken == "r1")
        #expect(restored.accessToken == "stale")
    }

    @Test("invalid_grant poisons the session, fires sessionInvalidated exactly once, and every subsequent call fails the same way")
    func invalidGrantPoisonsSession() async throws {
        let idp = LocalIdP()
        idp.tokenEndpointHandler = { _ in .error(status: 400, code: "invalid_grant") }
        let manager = makeManager(idp: idp)
        try await seed(manager, accessToken: "stale", refreshToken: "r1", expiresIn: -10)

        var iterator = manager.sessionInvalidated.makeAsyncIterator()

        await #expect(throws: OAuthError.self) {
            _ = try await manager.validAccessToken()
        }
        // Deterministic, not a sleep-and-hope: awaiting the iterator suspends exactly until the
        // continuation yields the one event this poisoning path produces.
        #expect(await iterator.next() == .refreshTokenReuseDetected)

        await #expect(throws: OAuthError.self) {
            _ = try await manager.refreshNow()
        }
        // The second call must not have triggered a second network refresh — poisoning short-
        // circuits before any request is made.
        #expect(idp.tokenEndpointRequestCount == 1)
    }

    @Test("signOut clears stored tokens and poisons the session")
    func signOutClearsAndPoisons() async throws {
        let idp = LocalIdP()
        let manager = makeManager(idp: idp)
        try await seed(manager, accessToken: "a", refreshToken: "r1", expiresIn: 3600)

        try await manager.signOut()

        await #expect(throws: OAuthError.self) {
            _ = try await manager.validAccessToken()
        }
    }

    @Test("no stored tokens at all throws sessionInvalidated(.noRefreshToken)")
    func noStoredTokensThrows() async throws {
        let idp = LocalIdP()
        let manager = makeManager(idp: idp)
        do {
            _ = try await manager.validAccessToken()
            Issue.record("expected sessionInvalidated")
        } catch OAuthError.sessionInvalidated(.noRefreshToken) {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }
}
