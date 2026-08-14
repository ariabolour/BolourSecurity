/// What happens when a connection targets a host with no applicable ``PinningPolicy``.
public enum UnpinnedHostBehavior: Sendable {
    /// Hosts without a pin get standard system trust. The default; correct for most apps —
    /// third-party endpoints (analytics, CDNs) keep working without a "pin everything" outage.
    case systemTrust
    /// Hosts without a pin are refused. For closed-world apps that talk only to known hosts.
    case refuse
}
