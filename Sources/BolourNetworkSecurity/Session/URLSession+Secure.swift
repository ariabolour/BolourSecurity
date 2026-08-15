import Foundation
import Network

extension URLSession {
    /// A session whose server-trust handling enforces `policy`. Fails closed: any evaluation
    /// error, or an unpinned host under `.refuse`, cancels the challenge — there is no code
    /// path that falls through to default handling for a pinned host.
    ///
    /// `policy.minimumTLS` is applied to `configuration.tlsMinimumSupportedProtocolVersion`
    /// before the session is created: the floor is therefore enforced by the OS at the TLS
    /// handshake itself, for every connection this session makes, not just the ones that reach
    /// our delegate.
    public static func secure(
        policy: NetworkSecurityPolicy,
        configuration: URLSessionConfiguration = .ephemeral,
        delegate: (any URLSessionDelegate)? = nil,
        delegateQueue: OperationQueue? = nil
    ) -> URLSession {
        configuration.tlsMinimumSupportedProtocolVersion = policy.minimumTLS.protocolVersion
        let secureDelegate = SecureSessionDelegate(policy: policy, forwardingTo: delegate)
        return URLSession(configuration: configuration, delegate: secureDelegate, delegateQueue: delegateQueue)
    }
}
