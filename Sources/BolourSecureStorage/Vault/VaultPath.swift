import Foundation

/// A logical path inside a `Vault`. Normalized and validated at construction: traversal (`..`),
/// current-directory (`.`), and absolute-looking (leading `/`) components are unrepresentable —
/// there is no way to build a `VaultPath` that resolves outside the vault, because the
/// *on-disk* name a path maps to is always a fresh random identifier the manifest generates
/// (see `Vault`), never derived from the path text at all.
public struct VaultPath: Sendable, Hashable {
    let components: [String]

    private init(components: [String]) { self.components = components }

    /// The vault's top-level directory.
    public static var root: VaultPath { VaultPath(components: []) }

    /// Validates and normalizes a runtime-constructed path string (e.g. built from user input).
    public init(validating string: String) throws(StorageError) {
        guard !string.hasPrefix("/") else {
            throw StorageError.underlying(VaultPathError.absolutePath(string))
        }
        let parts = string.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !parts.contains(where: { $0 == ".." || $0 == "." || $0.isEmpty }) else {
            throw StorageError.underlying(VaultPathError.invalidComponent(string))
        }
        self.components = parts
    }

    /// The flattened form used as the manifest's dictionary key.
    var storageKey: String { components.joined(separator: "/") }

    /// Reconstructs a path from an already-validated manifest key. Not validated again — every
    /// key in the manifest was validated when it was first written.
    init(storageKey: String) {
        self.components = storageKey.isEmpty ? [] : storageKey.split(separator: "/").map(String.init)
    }
}

extension VaultPath: ExpressibleByStringLiteral {
    /// Developer-authored, static text: invalid literals fail loudly at development time (a
    /// crash), the same "impossible to ship" contract as `AuthenticationReason`. Runtime text
    /// should use ``init(validating:)`` instead, which reports the same problem as a typed throw.
    public init(stringLiteral value: String) {
        precondition(!value.hasPrefix("/"), "VaultPath literal must not be absolute: \(value)")
        let parts = value.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        precondition(
            !parts.contains(where: { $0 == ".." || $0 == "." || $0.isEmpty }),
            "VaultPath literal must not contain traversal or empty components: \(value)"
        )
        self.components = parts
    }
}

extension VaultPath: CustomStringConvertible {
    public var description: String { "/" + storageKey }
}

enum VaultPathError: Error, Sendable {
    case absolutePath(String)
    case invalidComponent(String)
}
