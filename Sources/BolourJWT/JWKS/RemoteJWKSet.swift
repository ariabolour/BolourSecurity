import Foundation

/// Fetches a JWK Set over `session` and caches it for `cachePolicy.ttl`. Concurrent callers that
/// all find the cache stale collapse onto one in-flight fetch — never a refresh stampede.
///
/// - Note: v1.0 scope is TTL-based caching, not `Cache-Control` header honoring — a documented
///   simplification of the design's fuller "honors cache policy, single bounded refresh on
///   kid-miss" description. A short `cachePolicy.ttl` is the workaround for apps that need to
///   pick up rotated keys quickly.
public actor RemoteJWKSet: JWKSProviding {
    private let url: URL
    private let session: URLSession
    private let cachePolicy: JWKSCachePolicy
    private var cached: (keys: [any JWTVerificationKey], fetchedAt: Date)?
    private var inFlightFetch: Task<[any JWTVerificationKey], any Error>?

    public init(url: URL, session: URLSession = .shared, cachePolicy: JWKSCachePolicy = .default) {
        self.url = url
        self.session = session
        self.cachePolicy = cachePolicy
    }

    public func currentKeys() async throws -> [any JWTVerificationKey] {
        if let cached, !isStale(cached.fetchedAt) {
            return cached.keys
        }
        return try await fetch()
    }

    private func isStale(_ fetchedAt: Date) -> Bool {
        Date().timeIntervalSince(fetchedAt) > cachePolicy.ttl.timeInterval
    }

    private func fetch() async throws -> [any JWTVerificationKey] {
        if let inFlightFetch {
            return try await inFlightFetch.value
        }
        let url = self.url
        let session = self.session
        let task = Task<[any JWTVerificationKey], any Error> {
            let (data, _) = try await session.data(from: url)
            return try JSONDecoder().decode(JWKSet.self, from: data).verificationKeys()
        }
        inFlightFetch = task
        defer { inFlightFetch = nil }

        let keys = try await task.value
        cached = (keys, Date())
        return keys
    }
}
