import Testing
import Foundation
@testable import BlurNetworkSecurity

/// Proves `SecureSessionDelegate` owns exactly the server-trust decision and forwards
/// everything else — every other challenge type, and every other delegate callback entirely —
/// to a composed app delegate, using real `URLSessionTaskDelegate` dispatch (direct calls for
/// the challenge methods themselves; real ObjC message forwarding, exercised through an
/// in-process `URLProtocol` stub, for callbacks `SecureSessionDelegate` never implements).
@Suite("Delegate composition and forwarding")
struct DelegateForwardingTests {

    /// Fails every request it handles immediately, with no real I/O — so the
    /// `didCompleteWithError` forwarding proof doesn't depend on how this machine's network
    /// stack happens to react to an unanswered loopback connection.
    final class ImmediateFailureProtocol: URLProtocol, @unchecked Sendable {
        override class func canInit(with request: URLRequest) -> Bool { request.url?.scheme == "immediate-failure" }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func startLoading() {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
        }
        override func stopLoading() {}
    }

    final class RecordingDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        private let lock = NSLock()
        private var _taskChallengeReceived = false
        private var _sessionChallengeReceived = false
        private var _didFinishCollectingMetricsReceived = false
        var onDidFinishCollectingMetrics: (@Sendable () -> Void)?

        var taskChallengeReceived: Bool { lock.lock(); defer { lock.unlock() }; return _taskChallengeReceived }
        var sessionChallengeReceived: Bool { lock.lock(); defer { lock.unlock() }; return _sessionChallengeReceived }
        var didFinishCollectingMetricsReceived: Bool { lock.lock(); defer { lock.unlock() }; return _didFinishCollectingMetricsReceived }

        func urlSession(
            _ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            lock.lock(); _taskChallengeReceived = true; lock.unlock()
            completionHandler(.performDefaultHandling, nil)
        }

        func urlSession(
            _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            lock.lock(); _sessionChallengeReceived = true; lock.unlock()
            completionHandler(.performDefaultHandling, nil)
        }

        // `didCompleteWithError` is deliberately *not* implemented here: Apple skips it (and
        // `didReceive data:`) for tasks created via the completion-handler convenience API
        // (`session.data(from:)`, `dataTask(with:completionHandler:)`) — the completion handler
        // stands in for it instead. `didFinishCollectingMetrics` is not skipped for those tasks,
        // so it is what this suite uses to prove forwarding of a callback SecureSessionDelegate
        // never implements.
        func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
            lock.lock(); _didFinishCollectingMetricsReceived = true; lock.unlock()
            onDidFinishCollectingMetrics?()
        }
    }

    final class DummySender: NSObject, URLAuthenticationChallengeSender {
        func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
        func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
        func cancel(_ challenge: URLAuthenticationChallenge) {}
    }

    private func clientCertificateChallenge(host: String = "localhost") -> URLAuthenticationChallenge {
        let space = URLProtectionSpace(
            host: host, port: 443, protocol: "https", realm: nil,
            authenticationMethod: NSURLAuthenticationMethodClientCertificate
        )
        return URLAuthenticationChallenge(
            protectionSpace: space, proposedCredential: nil,
            previousFailureCount: 0, failureResponse: nil, error: nil, sender: DummySender()
        )
    }

    @Test("a non-server-trust challenge forwards at the task level")
    func forwardsNonTrustChallengeAtTaskLevel() async {
        let recorder = RecordingDelegate()
        let secureDelegate = SecureSessionDelegate(policy: NetworkSecurityPolicy(), forwardingTo: recorder)
        let session = URLSession(configuration: .ephemeral)
        let task = session.dataTask(with: URL(string: "https://localhost/")!)
        defer { task.cancel() }

        let disposition = await withCheckedContinuation { (continuation: CheckedContinuation<URLSession.AuthChallengeDisposition, Never>) in
            secureDelegate.urlSession(session, task: task, didReceive: clientCertificateChallenge()) { result, _ in
                continuation.resume(returning: result)
            }
        }
        #expect(recorder.taskChallengeReceived)
        #expect(disposition == .performDefaultHandling)
    }

    @Test("a non-server-trust challenge forwards at the session level")
    func forwardsNonTrustChallengeAtSessionLevel() async {
        let recorder = RecordingDelegate()
        let secureDelegate = SecureSessionDelegate(policy: NetworkSecurityPolicy(), forwardingTo: recorder)
        let session = URLSession(configuration: .ephemeral)

        let disposition = await withCheckedContinuation { (continuation: CheckedContinuation<URLSession.AuthChallengeDisposition, Never>) in
            secureDelegate.urlSession(session, didReceive: clientCertificateChallenge()) { result, _ in
                continuation.resume(returning: result)
            }
        }
        #expect(recorder.sessionChallengeReceived)
        #expect(disposition == .performDefaultHandling)
    }

    @Test("a non-server-trust challenge performs default handling with no composed delegate")
    func defaultHandlingWithoutForward() async {
        let secureDelegate = SecureSessionDelegate(policy: NetworkSecurityPolicy(), forwardingTo: nil)
        let session = URLSession(configuration: .ephemeral)

        let disposition = await withCheckedContinuation { (continuation: CheckedContinuation<URLSession.AuthChallengeDisposition, Never>) in
            secureDelegate.urlSession(session, didReceive: clientCertificateChallenge()) { result, _ in
                continuation.resume(returning: result)
            }
        }
        #expect(disposition == .performDefaultHandling)
    }

    @Test("responds(to:) is true for a selector only the composed delegate implements")
    func respondsToTracksForwardTarget() {
        let selector = #selector(URLSessionTaskDelegate.urlSession(_:task:didFinishCollecting:))
        let withForward = SecureSessionDelegate(policy: NetworkSecurityPolicy(), forwardingTo: RecordingDelegate())
        let withoutForward = SecureSessionDelegate(policy: NetworkSecurityPolicy(), forwardingTo: nil)
        #expect(withForward.responds(to: selector))
        #expect(!withoutForward.responds(to: selector))
    }

    @Test("didFinishCollectingMetrics forwards via ObjC message forwarding")
    func endToEndForwardingViaRuntimeDispatch() async {
        let recorder = RecordingDelegate()
        let secureDelegate = SecureSessionDelegate(policy: NetworkSecurityPolicy(), forwardingTo: recorder)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ImmediateFailureProtocol.self]
        let session = URLSession(configuration: configuration, delegate: secureDelegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        // The stub protocol fails every request with no real I/O. `didFinishCollectingMetrics`
        // is called for every task regardless of how it was created (unlike `didCompleteWithError`,
        // which Apple skips for completion-handler-based tasks) — a callback SecureSessionDelegate
        // never implements itself, so this only succeeds if `forwardingTarget(for:)` is really
        // routing it to `recorder`.
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            recorder.onDidFinishCollectingMetrics = { continuation.resume() }
            Task {
                _ = try? await session.data(from: URL(string: "immediate-failure://test/")!)
            }
        }
        #expect(recorder.didFinishCollectingMetricsReceived)
    }
}
