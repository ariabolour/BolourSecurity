import Foundation
import Security
import BlurCertificates
import BlurSecurityCore

/// The trust-only delegate: apps that must own their `URLSession` compose this in manually
/// instead of going through ``URLSession/secure(policy:configuration:delegate:delegateQueue:)``.
///
/// It implements server-trust challenge handling at **both** the task level
/// (`urlSession(_:task:didReceive:completionHandler:)`) and the session level
/// (`urlSession(_:didReceive:completionHandler:)`) and owns exactly that one decision on both
/// paths — `URLSession` prefers the task-level callback when a delegate implements it, and a
/// composed app delegate implementing only the task-level method must not let server-trust
/// challenges slip past us on that path. Every other challenge type, and every other delegate
/// callback entirely, is forwarded untouched to `forwardTo` via Objective-C message forwarding
/// (`forwardingTarget(for:)`): we never re-declare the dozens of `URLSessionTaskDelegate` /
/// `URLSessionDataDelegate` / … methods, so composition automatically tracks whatever richer
/// delegate protocols the app's own delegate conforms to.
///
/// - Important: `@unchecked Sendable` — `forwardTo` is a plain `(any URLSessionDelegate)?`,
///   which Foundation does not mark `Sendable`. It is stored once at `init` and never mutated
///   afterward, and `URLSession` already invokes delegate callbacks concurrently from its own
///   delegate queue, so composing over it introduces no new shared mutable state. Same
///   justification class as `BlurBiometrics`' `LAContext` box (ADR-0003).
public final class SecureSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let policy: NetworkSecurityPolicy
    private let forwardTo: (any URLSessionDelegate)?
    private let evaluator: any ChainEvaluating

    public init(policy: NetworkSecurityPolicy, forwardingTo delegate: (any URLSessionDelegate)? = nil) {
        self.policy = policy
        self.forwardTo = delegate
        self.evaluator = TrustEvaluator(pinning: policy.pinning, logger: policy.logger)
        super.init()
    }

    /// Test-only: substitutes `evaluator` (a fault-injectable double, or a `TrustEvaluator`
    /// carrying test anchors) for the one built from `policy.pinning`.
    init(policy: NetworkSecurityPolicy, forwardingTo delegate: (any URLSessionDelegate)? = nil, evaluator: any ChainEvaluating) {
        self.policy = policy
        self.forwardTo = delegate
        self.evaluator = evaluator
        super.init()
    }

    public override func responds(to selector: Selector!) -> Bool {
        super.responds(to: selector) || (forwardTo?.responds(to: selector) ?? false)
    }

    public override func forwardingTarget(for selector: Selector!) -> Any? {
        // Only reached for selectors we don't implement ourselves.
        forwardTo
    }

    // MARK: - Task-level challenge (preferred by URLSession when implemented)

    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handle(session: session, challenge: challenge, completionHandler: completionHandler) {
            // A composed delegate may implement only one of the two challenge levels (many
            // apps do); an optional-protocol call to a method it doesn't implement is a silent
            // no-op that never calls `completionHandler`, so each step must be gated by
            // `responds(to:)` before it is attempted, falling all the way through to default
            // handling rather than risking a hung challenge.
            if let taskDelegate = self.forwardTo as? any URLSessionTaskDelegate,
               taskDelegate.responds(to: #selector(URLSessionTaskDelegate.urlSession(_:task:didReceive:completionHandler:))) {
                taskDelegate.urlSession?(session, task: task, didReceive: challenge, completionHandler: completionHandler)
            } else if let delegate = self.forwardTo,
                      delegate.responds(to: #selector(URLSessionDelegate.urlSession(_:didReceive:completionHandler:))) {
                delegate.urlSession?(session, didReceive: challenge, completionHandler: completionHandler)
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        }
    }

    // MARK: - Session-level challenge (the fallback URLSession uses otherwise)

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handle(session: session, challenge: challenge, completionHandler: completionHandler) {
            if let forwardTo = self.forwardTo,
               forwardTo.responds(to: #selector(URLSessionDelegate.urlSession(_:didReceive:completionHandler:))) {
                forwardTo.urlSession?(session, didReceive: challenge, completionHandler: completionHandler)
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        }
    }

    // MARK: - The one decision

    private func handle(
        session: URLSession,
        challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void,
        forward: @escaping @Sendable () -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust
        else {
            forward()
            return
        }

        let host = challenge.protectionSpace.host
        Task {
            do {
                let credential = try await self.decide(serverTrust: serverTrust, host: host)
                completionHandler(.useCredential, credential)
            } catch {
                // Fail closed: any evaluation error, or an unpinned host under `.refuse`,
                // cancels the challenge. There is no path to `.performDefaultHandling` here.
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }

    /// Not `private`: exercised directly by tests that fault-inject `evaluator` and assert the
    /// fail-closed property without needing a live TLS connection for every case.
    func decide(serverTrust: SecTrust, host: String) async throws(PinningEnforcementError) -> URLCredential {
        if let override = policy.override, override.hosts.contains(host.lowercased()) {
            return URLCredential(trust: serverTrust)
        }

        let chain: CertificateChain
        do {
            chain = try CertificateChain(presentedBy: serverTrust)
        } catch {
            throw PinningEnforcementError.evaluationFailed(host: host, underlying: error)
        }

        let evaluated: EvaluatedCertificateChain
        do {
            evaluated = try await evaluator.evaluate(chain, for: host)
        } catch {
            throw PinningEnforcementError.evaluationFailed(host: host, underlying: error)
        }

        if evaluated.matchedPin == nil, case .refuse = policy.unpinnedHostBehavior {
            policy.logger?.log(.pinningFailure(host: host))
            throw PinningEnforcementError.unpinnedHostRefused(host: host)
        }
        return URLCredential(trust: serverTrust)
    }
}
