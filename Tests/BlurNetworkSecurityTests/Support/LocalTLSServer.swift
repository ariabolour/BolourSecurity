import Foundation
import Network
import Security

/// A minimal, in-process HTTPS server used only to exercise the real TLS/challenge machinery
/// end to end: bound to the loopback interface, terminates real TLS with a test `SecIdentity`,
/// and answers any request with a canned 200. It exists so `SecureSessionDelegate` tests observe
/// the actual `URLAuthenticationChallenge` a live connection produces, not a hand-built stand-in.
///
/// `@unchecked Sendable`: `NWListener`/`NWConnection` are reference types invoked from Network's
/// own internal queue; all mutable state here is confined to `queue` and never touched off it.
final class LocalTLSServer: @unchecked Sendable {
    private let queue = DispatchQueue(label: "LocalTLSServer")
    private var listener: NWListener?
    private var connections: [ObjectIdentifier: NWConnection] = [:]

    /// The assigned loopback port, valid once `start` returns.
    private(set) var port: UInt16 = 0

    /// Starts listening on loopback-only, using `identity` and a TLS version window.
    func start(
        identity: SecIdentity,
        minimumVersion: tls_protocol_version_t = .TLSv12,
        maximumVersion: tls_protocol_version_t = .TLSv13
    ) async throws {
        guard let secIdentity = sec_identity_create(identity) else {
            throw LocalTLSServerError.identityCreationFailed
        }

        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tlsOptions.securityProtocolOptions, secIdentity)
        sec_protocol_options_set_min_tls_protocol_version(tlsOptions.securityProtocolOptions, minimumVersion)
        sec_protocol_options_set_max_tls_protocol_version(tlsOptions.securityProtocolOptions, maximumVersion)

        let parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        parameters.requiredInterfaceType = .loopback
        parameters.allowLocalEndpointReuse = true

        let newListener = try NWListener(using: parameters)
        self.listener = newListener

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            // Network.framework invokes `stateUpdateHandler` serially on `queue`, so replacing
            // the handler with a no-op from within itself (rather than guarding a captured
            // `Bool`) is race-free and needs no lock: no later invocation can already be
            // in flight when the reassignment takes effect.
            newListener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    self.port = newListener.port?.rawValue ?? 0
                    newListener.stateUpdateHandler = { _ in }
                    continuation.resume()
                case .failed(let error):
                    newListener.stateUpdateHandler = { _ in }
                    continuation.resume(throwing: error)
                default:
                    break
                }
            }
            newListener.newConnectionHandler = { [weak self] connection in
                self?.accept(connection)
            }
            newListener.start(queue: queue)
        }
    }

    private func accept(_ connection: NWConnection) {
        let key = ObjectIdentifier(connection)
        connections[key] = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .failed, .cancelled:
                self.queue.async { [self] in self.connections.removeValue(forKey: key) }
            default:
                break
            }
        }
        connection.start(queue: queue)
        receiveRequest(on: connection, accumulated: Data())
    }

    /// Reads until a full header block arrives (or the connection ends), then answers with a
    /// fixed 200 response and closes. Good enough for exercising the TLS/trust path — this is
    /// not a real HTTP server.
    private func receiveRequest(on connection: NWConnection, accumulated: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            var buffer = accumulated
            if let data { buffer.append(data) }

            if error != nil || (isComplete && data == nil) {
                connection.cancel()
                return
            }

            if buffer.range(of: Data("\r\n\r\n".utf8)) != nil {
                let body = "ok"
                let response = "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
                connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in
                    connection.cancel()
                })
                return
            }

            self.receiveRequest(on: connection, accumulated: buffer)
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        for (_, connection) in connections { connection.cancel() }
        connections.removeAll()
    }

    deinit {
        listener?.cancel()
        for (_, connection) in connections { connection.cancel() }
    }
}

enum LocalTLSServerError: Error {
    case identityCreationFailed
}
