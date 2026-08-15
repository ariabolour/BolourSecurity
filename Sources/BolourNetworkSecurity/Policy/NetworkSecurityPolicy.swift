import BolourCertificates
import BolourSecurityCore

/// Session-level TLS policy and certificate pinning, as one declarative value.
///
/// A `NetworkSecurityPolicy` says nothing on its own — it becomes enforcement only through
/// ``URLSession/secure(policy:configuration:delegate:delegateQueue:)`` or a manually composed
/// ``SecureSessionDelegate``. Only connections made through that session are protected; this is
/// documented loudly because a shared, unrelated session is the classic "pinning theater" bug.
public struct NetworkSecurityPolicy: Sendable {
    let pinning: [PinningPolicy]
    let minimumTLS: TLSVersion
    let unpinnedHostBehavior: UnpinnedHostBehavior
    let logger: (any SecurityEventLogger)?
    let override: UnvalidatedTrustOverride?

    public init(
        pinning: [PinningPolicy] = [],
        minimumTLS: TLSVersion = .v1_2,
        unpinnedHostBehavior: UnpinnedHostBehavior = .systemTrust,
        logger: (any SecurityEventLogger)? = nil
    ) {
        self.pinning = pinning
        self.minimumTLS = minimumTLS
        self.unpinnedHostBehavior = unpinnedHostBehavior
        self.logger = logger
        self.override = nil
    }

    private init(reusing base: NetworkSecurityPolicy, override: UnvalidatedTrustOverride) {
        self.pinning = base.pinning
        self.minimumTLS = base.minimumTLS
        self.unpinnedHostBehavior = base.unpinnedHostBehavior
        self.logger = base.logger
        self.override = override
    }

    /// Returns a policy that additionally accepts `override`'s hosts without trust evaluation.
    /// Intended for `#if DEBUG`-gated call sites only; the override's own construction already
    /// restricts it to local-development hosts.
    public func allowing(_ override: UnvalidatedTrustOverride) -> NetworkSecurityPolicy {
        NetworkSecurityPolicy(reusing: self, override: override)
    }
}
