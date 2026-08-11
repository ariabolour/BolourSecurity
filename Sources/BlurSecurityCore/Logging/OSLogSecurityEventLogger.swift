import os

/// The default ``SecurityEventLogger``, backed by `os.Logger`.
///
/// Each event maps to a static message; the only interpolated values are non-secret (e.g. a
/// hostname on a pinning failure, logged with `.public` privacy because it is not sensitive).
public struct OSLogSecurityEventLogger: SecurityEventLogger {
    private let logger: Logger

    /// Creates a logger writing to `subsystem` / `category`.
    public init(subsystem: String = "BlurSecurity", category: String = "security") {
        self.logger = Logger(subsystem: subsystem, category: category)
    }

    public func log(_ event: SecurityEvent) {
        switch event.kind {
        case .itemStored:
            logger.info("Secret item stored")
        case .itemRead:
            logger.info("Secret item read")
        case .itemRemoved:
            logger.info("Secret item removed")
        case .authenticationSucceeded:
            logger.info("Local authentication succeeded")
        case .authenticationFailed:
            logger.notice("Local authentication failed")
        case .pinningFailure(let host):
            logger.error("Certificate pinning failed for host \(host, privacy: .public)")
        }
    }
}
