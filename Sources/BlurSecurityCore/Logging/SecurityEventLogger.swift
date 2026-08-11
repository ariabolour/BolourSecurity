/// A sink for structured ``SecurityEvent`` values.
///
/// Because events are a closed, pre-redacted set, a logger cannot become a secret-leaking
/// channel no matter how it is implemented. Apps inject a concrete logger; the ecosystem
/// default is ``OSLogSecurityEventLogger``.
public protocol SecurityEventLogger: Sendable {
    /// Records `event`.
    func log(_ event: SecurityEvent)
}
