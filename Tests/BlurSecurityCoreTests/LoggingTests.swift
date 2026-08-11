import Testing
import Foundation
import BlurSecurityCore

@Suite("Security event logging")
struct LoggingTests {

    @Test("the default logger accepts every event kind")
    func logsAllKinds() {
        let logger = OSLogSecurityEventLogger(subsystem: "BlurSecurityTests", category: "test")
        let events: [SecurityEvent] = [
            .itemStored, .itemRead, .itemRemoved,
            .authenticationSucceeded, .authenticationFailed,
            .pinningFailure(host: "example.com"),
        ]
        for event in events {
            logger.log(event)   // must not crash
        }
        #expect(events.count == 6)
    }

    @Test("a custom logger receives the events it is given")
    func customLogger() {
        // A test double satisfying the Core seam.
        final class Collector: SecurityEventLogger, @unchecked Sendable {
            private let lock = NSLock()
            private var storage: [SecurityEvent] = []
            var events: [SecurityEvent] {
                lock.lock(); defer { lock.unlock() }
                return storage
            }
            func log(_ event: SecurityEvent) {
                lock.lock(); defer { lock.unlock() }
                storage.append(event)
            }
        }

        let collector = Collector()
        collector.log(.itemStored)
        collector.log(.pinningFailure(host: "api.example.com"))
        #expect(collector.events == [.itemStored, .pinningFailure(host: "api.example.com")])
    }
}
