# BolourNetworkSecurity

**Layer 3 · Protocols & Services.** Certificate pinning and TLS policy, enforced where the connections actually happen.

## Mission

Close the gap between *having* a pinning policy (`BolourCertificates`) and *enforcing* it on every connection: one line to obtain a `URLSession` whose authentication-challenge handling is correct, fail-closed, and impossible to accidentally bypass — plus honest guidance for the flows a library cannot see (ATS, WKWebView, third-party networking stacks).

## Responsibilities

- `URLSession` integration: a delegate that evaluates server trust through `TrustEvaluating` and answers challenges correctly, and a factory that builds sessions wired to it.
- Session-level TLS policy (minimum version, per-host pinning sets) as one declarative value.
- Composition with app-owned delegates (apps keep their metrics/redirect delegates; we own only the trust decision).
- A structured escape hatch for local development that cannot be shipped silently.
- Documentation ownership of the "pinning in WKWebView / ATS interplay / streaming APIs" reality.

## Public API (signature-level design)

```swift
public struct NetworkSecurityPolicy: Sendable {
    public init(
        pinning: [PinningPolicy] = [],
        minimumTLS: TLSVersion = .v1_2,
        unpinnedHostBehavior: UnpinnedHostBehavior = .systemTrust,
        logger: (any SecurityEventLogger)? = nil
    )
}

public enum UnpinnedHostBehavior: Sendable {
    /// Hosts without a pin get standard system trust. The default; correct for most apps.
    case systemTrust
    /// Hosts without a pin are REFUSED. For closed-world apps that talk only to known hosts.
    case refuse
}

public enum TLSVersion: Sendable, Comparable { case v1_2, v1_3 }

extension URLSession {
    /// A session whose server-trust handling enforces `policy`. Fails closed:
    /// any evaluation error cancels the challenge.
    public static func secure(
        policy: NetworkSecurityPolicy,
        configuration: URLSessionConfiguration = .ephemeral,   // no shared cookie/cache state by default
        delegate: (any URLSessionDelegate)? = nil,             // app delegate composed, trust decisions ours
        delegateQueue: OperationQueue? = nil
    ) -> URLSession
}

/// For apps that must own their session: the trust-only delegate to compose manually.
public final class SecureSessionDelegate: NSObject, URLSessionDelegate, Sendable {
    public init(policy: NetworkSecurityPolicy, forwardingTo delegate: (any URLSessionDelegate)? = nil)
}

/// Local-development escape hatch. Deliberately unpleasant to ship:
/// the name is self-indicting, construction logs a warning-level SecurityEvent,
/// and it refuses non-private hosts (only *.local, localhost, RFC1918/loopback).
public struct UnvalidatedTrustOverride: Sendable {
    public init(forLocalDevelopmentHosts hosts: Set<String>) throws(PinningEnforcementError)
}
public struct NetworkSecurityPolicy { // (extension shown separately for emphasis)
    public func allowing(_ override: UnvalidatedTrustOverride) -> NetworkSecurityPolicy
}

public enum PinningEnforcementError: SecurityError {
    case evaluationFailed(host: String, underlying: CertificateError)
    case unpinnedHostRefused(host: String)
    case tlsVersionBelowMinimum(host: String)
    case overrideHostNotLocal(String)              // tried to "unvalidate" a real host: refused
}
```

## Dependencies

`BolourSecurityCore`, `BolourCertificates`; Apple: Foundation (URLSession), Network (types only, for host classification).

## Architecture

- The delegate implements `urlSession(_:didReceive:completionHandler:)` for `NSURLAuthenticationMethodServerTrust` **only**; every other challenge type and every other delegate callback forwards untouched to the composed app delegate. We own exactly one decision, and composition is therefore safe.
- Trust evaluation extracts the presented chain, converts to `CertificateChain`, and calls `TrustEvaluating.evaluate` — the single trust path shared with direct `BolourCertificates` users. On success: `.useCredential` with the evaluated trust. On *any* failure or thrown error: `.cancelAuthenticationChallenge`. There is no code path that answers `.performDefaultHandling` for a pinned host — fail-open-by-forwarding is structurally absent.
- The completion-handler ↔ async bridge is internal; public API stays async/await-native and the delegate remains usable from Objective-C-adjacent stacks.
- `UnvalidatedTrustOverride` validates hosts at *construction* (throwing on public hosts), so the misuse fails at the developer's desk, not in a security review three releases later.

## Usage Examples

```swift
import BolourNetworkSecurity

let policy = NetworkSecurityPolicy(
    pinning: [apiPins],                       // from BolourCertificates
    minimumTLS: .v1_3
)
let session = URLSession.secure(policy: policy)
let (data, response) = try await session.data(from: apiURL)   // pinning enforced, fail-closed

#if DEBUG
let devPolicy = policy.allowing(
    try UnvalidatedTrustOverride(forLocalDevelopmentHosts: ["localhost"])
)
#endif
```

## Testing Strategy

- **Local TLS harness:** integration tests run against an in-process TLS server (Network.framework listener) with generated test CAs — matrix over {pinned-match, pinned-mismatch, unpinned + systemTrust, unpinned + refuse, expired pin set, TLS 1.2 vs 1.3 floors}; asserts both the connection outcome and the emitted `SecurityEvent`s.
- Delegate-composition tests: an app delegate implementing every `URLSessionTaskDelegate` method verifies all non-trust callbacks arrive; a challenge-type matrix verifies only server-trust is intercepted (client-cert challenges forward).
- Fail-closed property test: fault-injected evaluator (throws, hangs, returns malformed) ⇒ challenge always cancelled, never default-handled.
- `UnvalidatedTrustOverride` host-classification table tests (public hostnames refused; loopback/RFC1918/.local accepted).
- Concurrency: hundreds of simultaneous requests across pinned hosts; evaluation results are per-host cached within documented TTL without cross-host bleed.

## Security Considerations & Common Mistakes Prevented

- **Prevented: the fail-open pinning bug** — the most common real-world pinning vulnerability is a delegate that falls through to `performDefaultHandling` on unexpected paths. Our delegate has no such path.
- **Prevented: "pin everything" outages** — `.systemTrust` default for unpinned hosts keeps third-party endpoints (analytics, CDNs) working; `.refuse` is the explicit closed-world choice.
- **Prevented: shipping the dev bypass** — override construction refuses non-local hosts and screams into the security log.
- **Prevented: pinning theater via shared sessions** — docs lead with the rule that only connections through the secured session are protected; the API returns *the session* rather than mutating global state precisely so the protected path is nameable and testable in the app's own tests.
- **Honest limits (documented, prominently):** WKWebView's trust handling offers only accept/reject via its own delegate (article shows the pattern using our evaluator); `URLSession` background sessions and some streaming paths deliver challenges with constraints the article enumerates; ATS remains the app-level floor and we explain how our policy layers above it, not instead of it.

## Future Roadmap

- mTLS client-identity support (with `BolourCertificates` identities) (v2.0).
- Per-request policy scoping (`session.data(from:overriding:)`) for multi-tenant hosts (v2.x, if real demand materializes — API surface is a liability).
- Network.framework (`NWConnection`) policy adapter for non-URLSession stacks (v2.x).
- CT/OCSP surfacing as `SecTrust` capabilities evolve (tracks BolourCertificates roadmap).
