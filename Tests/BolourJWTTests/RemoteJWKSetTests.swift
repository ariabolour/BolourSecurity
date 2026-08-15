import Testing
import Foundation
import BolourCrypto
@testable import BolourJWT

@Suite("RemoteJWKSet")
struct RemoteJWKSetTests {

    /// Serves a JWK Set body and counts requests, keyed by URL — Swift Testing runs test
    /// methods concurrently, so state shared across them (rather than per-URL) would make one
    /// test's request count observe another's traffic.
    final class CountingJWKSProtocol: URLProtocol, @unchecked Sendable {
        private static let lock = NSLock()
        nonisolated(unsafe) private static var bodies: [URL: Data] = [:]
        nonisolated(unsafe) private static var counts: [URL: Int] = [:]

        static func register(url: URL, body: Data) {
            lock.lock(); bodies[url] = body; counts[url] = 0; lock.unlock()
        }
        static func requestCount(for url: URL) -> Int {
            lock.lock(); defer { lock.unlock() }
            return counts[url] ?? 0
        }
        private static func recordRequest(for url: URL) -> Data {
            lock.lock(); defer { lock.unlock() }
            counts[url, default: 0] += 1
            return bodies[url] ?? Data()
        }

        override class func canInit(with request: URLRequest) -> Bool { request.url?.scheme == "counting-jwks" }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func startLoading() {
            let url = request.url!
            let body = CountingJWKSProtocol.recordRequest(for: url)
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        }
        override func stopLoading() {}
    }

    private func jwksBody(keyID: String) throws -> Data {
        let key = SigningKey<P256>.software()
        let rawBytes = [UInt8](key.verificationKey.rawRepresentation)
        let json: [String: Any] = [
            "keys": [[
                "kty": "EC", "crv": "P-256", "kid": keyID,
                "x": Base64URL.encode(Data(rawBytes[0..<32])),
                "y": Base64URL.encode(Data(rawBytes[32..<64])),
            ]]
        ]
        return try JSONSerialization.data(withJSONObject: json)
    }

    private func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CountingJWKSProtocol.self]
        return URLSession(configuration: configuration)
    }

    /// A fresh, test-unique URL so concurrently running tests never share a request counter.
    private func makeJWKSSetup(keyID: String = "k1") throws -> (url: URL, session: URLSession) {
        let url = URL(string: "counting-jwks://host/\(UUID().uuidString).json")!
        CountingJWKSProtocol.register(url: url, body: try jwksBody(keyID: keyID))
        return (url, makeSession())
    }

    @Test("currentKeys() fetches over the network and returns the parsed keys")
    func fetchesAndParses() async throws {
        let (url, session) = try makeJWKSSetup(keyID: "k1")
        let jwks = RemoteJWKSet(url: url, session: session)
        let keys = try await jwks.currentKeys()
        #expect(keys.count == 1)
        #expect(keys[0].keyID == "k1")
        #expect(CountingJWKSProtocol.requestCount(for: url) == 1)
    }

    @Test("a second call within the cache TTL does not refetch")
    func cachedWithinTTL() async throws {
        let (url, session) = try makeJWKSSetup()
        let jwks = RemoteJWKSet(url: url, session: session, cachePolicy: .default)
        _ = try await jwks.currentKeys()
        _ = try await jwks.currentKeys()
        #expect(CountingJWKSProtocol.requestCount(for: url) == 1)
    }

    @Test("N concurrent calls against a cold cache collapse onto exactly one fetch")
    func concurrentCallsCollapseToOneFetch() async throws {
        let (url, session) = try makeJWKSSetup()
        let jwks = RemoteJWKSet(url: url, session: session)

        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<20 {
                group.addTask { try await jwks.currentKeys().count }
            }
            for try await count in group { #expect(count == 1) }
        }
        #expect(CountingJWKSProtocol.requestCount(for: url) == 1)
    }

    @Test("a call after the TTL expires refetches")
    func refetchesAfterTTLExpires() async throws {
        let (url, session) = try makeJWKSSetup()
        let jwks = RemoteJWKSet(url: url, session: session, cachePolicy: JWKSCachePolicy(ttl: .milliseconds(1)))
        _ = try await jwks.currentKeys()
        try await Task.sleep(for: .milliseconds(50))
        _ = try await jwks.currentKeys()
        #expect(CountingJWKSProtocol.requestCount(for: url) == 2)
    }
}
