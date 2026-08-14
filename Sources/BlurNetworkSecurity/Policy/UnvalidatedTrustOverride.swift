import Network
import BlurSecurityCore

/// Local-development escape hatch. Deliberately unpleasant to ship: the name is self-indicting,
/// construction logs an error-level ``SecurityEvent`` unconditionally (through a fresh
/// ``OSLogSecurityEventLogger``, regardless of any logger the eventual policy is given, so this
/// cannot be silenced by app configuration), and it refuses to be built for anything but a
/// local-development host.
///
/// A host in the override set skips trust evaluation **entirely** — the connection is accepted
/// on presentation of any certificate, valid or not. That is what "unvalidated" means, and it is
/// why construction is restricted to hosts that structurally cannot be a real remote MITM
/// target: `localhost`, `*.local`, RFC 1918 private addresses, and loopback addresses.
public struct UnvalidatedTrustOverride: Sendable {
    let hosts: Set<String>

    /// Validates every host at construction time, so misuse (a real hostname slipping in)
    /// fails at the developer's desk — not in a security review three releases later.
    public init(forLocalDevelopmentHosts hosts: Set<String>) throws(PinningEnforcementError) {
        for host in hosts {
            guard UnvalidatedTrustOverride.isLocalDevelopmentHost(host) else {
                throw PinningEnforcementError.overrideHostNotLocal(host)
            }
        }
        let normalized = Set(hosts.map { $0.lowercased() })
        self.hosts = normalized
        OSLogSecurityEventLogger().log(.developmentTrustOverrideCreated(hosts: normalized))
    }

    /// Whether `host` is a local-development host: `localhost`, a `.local` name, an RFC 1918
    /// private IPv4 address, or a loopback address (IPv4 `127.0.0.0/8` or IPv6 `::1`).
    static func isLocalDevelopmentHost(_ host: String) -> Bool {
        let lowered = host.lowercased()
        if lowered == "localhost" { return true }
        if lowered.hasSuffix(".local") { return true }
        if let ipv4 = IPv4Address(host) { return ipv4.isLoopbackIPv4 || ipv4.isRFC1918Private }
        if let ipv6 = IPv6Address(host) { return ipv6.isLoopback }
        return false
    }
}

extension IPv4Address {
    /// Whether the address falls in the RFC 1122 loopback block `127.0.0.0/8`. `Network`'s own
    /// `isLoopback` only recognizes `127.0.0.1` itself, which is narrower than the block a
    /// local-development host can legitimately use.
    fileprivate var isLoopbackIPv4: Bool {
        [UInt8](rawValue).first == 127
    }

    /// Whether the address falls in an RFC 1918 private range: `10.0.0.0/8`, `172.16.0.0/12`,
    /// or `192.168.0.0/16`.
    fileprivate var isRFC1918Private: Bool {
        let octets = [UInt8](rawValue)
        guard octets.count == 4 else { return false }
        switch octets[0] {
        case 10: return true
        case 172: return (16...31).contains(octets[1])
        case 192: return octets[1] == 168
        default: return false
        }
    }
}
