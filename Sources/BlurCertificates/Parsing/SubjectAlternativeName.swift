import Foundation

/// A Subject Alternative Name entry. Hostname verification itself is `SecTrust`'s job; this is the
/// typed, introspectable view of what a certificate claims to cover.
public enum SubjectAlternativeName: Sendable, Hashable, CustomStringConvertible {
    case dnsName(String)
    case ipAddress(Data)
    case uri(String)

    public var description: String {
        switch self {
        case .dnsName(let name): return "DNS:\(name)"
        case .uri(let uri): return "URI:\(uri)"
        case .ipAddress(let data): return "IP:\(data.map { String($0) }.joined(separator: "."))"
        }
    }
}
