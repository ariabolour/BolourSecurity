import Foundation
import BlurCrypto
@testable import BlurJWT

/// A scripted in-process identity provider: discovery document, JWKS, and a token endpoint
/// whose behavior each test configures directly. Registered by a test-unique host (a UUID) so
/// concurrently running tests never share state — the same lesson `RemoteJWKSetTests` already
/// encoded for this exact reason.
final class LocalIdP: @unchecked Sendable {
    let host = UUID().uuidString
    var issuer: URL { URL(string: "local-idp://\(host)")! }

    let signingKey = SigningKey<P256>.software()
    private let lock = NSLock()

    /// Called for every token-endpoint POST; the test supplies the behavior.
    var tokenEndpointHandler: (@Sendable (_ form: [String: String]) -> TokenEndpointStub) = { _ in .success(accessToken: "at", refreshToken: nil, expiresIn: 3600) }

    private var _tokenEndpointRequestCount = 0
    private var _lastTokenForm: [String: String]?
    private var _pendingIDToken: String?
    private var _discoveryEndpointHostOverride: String?

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }

    var tokenEndpointRequestCount: Int { withLock { _tokenEndpointRequestCount } }
    var lastTokenForm: [String: String]? {
        get { withLock { _lastTokenForm } }
        set { withLock { _lastTokenForm = newValue } }
    }

    /// Set by `FakeAuthorizationSessionPresenting` (which sees the nonce in the outgoing
    /// authorization URL and can `await idToken(...)` since presenting itself is async) so the
    /// synchronous token-endpoint handler has an already-signed, nonce-matched ID token ready.
    var pendingIDToken: String? {
        get { withLock { _pendingIDToken } }
        set { withLock { _pendingIDToken = newValue } }
    }

    /// When set, the discovery document's authorization/token endpoints point at THIS host
    /// instead of the IdP's own — simulating a mix-up attack / misconfigured discovery response.
    var discoveryEndpointHostOverride: String? {
        get { withLock { _discoveryEndpointHostOverride } }
        set { withLock { _discoveryEndpointHostOverride = newValue } }
    }

    enum TokenEndpointStub {
        case success(accessToken: String, refreshToken: String?, expiresIn: Double?, idToken: String? = nil)
        case error(status: Int, code: String)
    }

    init() {
        LocalIdPProtocol.register(self)
    }

    /// Async on purpose: called directly by tests (which are themselves async) to precompute a
    /// token embedded into a `tokenEndpointHandler` closure — `handleRequest` itself runs inside
    /// `URLProtocol.startLoading()`, which is synchronous, so it can only ever return values
    /// tests already prepared ahead of time, never compute one on the fly.
    func idToken(subject: String, audience: String, nonce: String?) async throws -> String {
        struct Claims: JWTClaims {
            let iss: String; let sub: String; let aud: [String]; let nonce: String?
        }
        let signer = JWTSigner(key: signingKey, keyID: "idp-key")
        let signed = try await signer.sign(
            Claims(iss: issuer.absoluteString, sub: subject, aud: [audience], nonce: nonce),
            expiresIn: .seconds(300)
        )
        return signed.compactSerialization
    }

    func handleRequest(path: String, body: Data) -> (status: Int, data: Data) {
        switch path {
        case "/.well-known/openid-configuration":
            let endpointBase = discoveryEndpointHostOverride.map { "local-idp://\($0)" } ?? issuer.absoluteString
            let doc: [String: Any] = [
                "issuer": issuer.absoluteString,
                "authorization_endpoint": "\(endpointBase)/authorize",
                "token_endpoint": "\(endpointBase)/token",
                "revocation_endpoint": "\(issuer)/revoke",
                "jwks_uri": "\(issuer)/jwks",
            ]
            return (200, try! JSONSerialization.data(withJSONObject: doc))

        case "/jwks":
            let rawBytes = [UInt8](signingKey.verificationKey.rawRepresentation)
            let jwk: [String: Any] = [
                "kty": "EC", "crv": "P-256", "kid": "idp-key",
                "x": base64URL(Data(rawBytes[0..<32])), "y": base64URL(Data(rawBytes[32..<64])),
            ]
            return (200, try! JSONSerialization.data(withJSONObject: ["keys": [jwk]]))

        case "/token":
            let form = Self.parseForm(body)
            withLock { _tokenEndpointRequestCount += 1; _lastTokenForm = form }
            switch tokenEndpointHandler(form) {
            case .success(let accessToken, let refreshToken, let expiresIn, let idToken):
                var json: [String: Any] = ["access_token": accessToken, "token_type": "Bearer"]
                if let refreshToken { json["refresh_token"] = refreshToken }
                if let expiresIn { json["expires_in"] = expiresIn }
                if let idToken { json["id_token"] = idToken }
                return (200, try! JSONSerialization.data(withJSONObject: json))
            case .error(let status, let code):
                return (status, try! JSONSerialization.data(withJSONObject: ["error": code]))
            }

        case "/revoke":
            return (200, Data())

        default:
            return (404, Data())
        }
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func parseForm(_ body: Data) -> [String: String] {
        var result: [String: String] = [:]
        for pair in String(decoding: body, as: UTF8.self).split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            result[String(parts[0])] = String(parts[1]).removingPercentEncoding ?? String(parts[1])
        }
        return result
    }
}

final class LocalIdPProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var idps: [String: LocalIdP] = [:]

    static func register(_ idp: LocalIdP) {
        lock.lock(); idps[idp.host] = idp; lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool { request.url?.scheme == "local-idp" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let host = url.host else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        LocalIdPProtocol.lock.lock()
        let idp = LocalIdPProtocol.idps[host]
        LocalIdPProtocol.lock.unlock()
        guard let idp else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }

        var body = Data()
        if let stream = request.httpBodyStream {
            stream.open()
            let bufferSize = 4096
            var buffer = [UInt8](repeating: 0, count: bufferSize)
            while stream.hasBytesAvailable {
                let read = stream.read(&buffer, maxLength: bufferSize)
                if read > 0 { body.append(contentsOf: buffer[0..<read]) }
                else { break }
            }
            stream.close()
        } else if let httpBody = request.httpBody {
            body = httpBody
        }

        let (status, data) = idp.handleRequest(path: url.path, body: body)
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
