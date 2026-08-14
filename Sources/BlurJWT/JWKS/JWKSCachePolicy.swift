/// How long `RemoteJWKSet` trusts a fetched key set before refetching.
public struct JWKSCachePolicy: Sendable {
    let ttl: Duration
    public static let `default` = JWKSCachePolicy(ttl: .seconds(3600))
    public init(ttl: Duration) { self.ttl = ttl }
}
