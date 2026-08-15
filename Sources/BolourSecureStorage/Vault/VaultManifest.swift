import Foundation

/// The sealed index mapping logical `VaultPath`s to on-disk file names — kept as its own
/// encrypted artifact so directory listings on disk reveal nothing about the vault's contents.
struct VaultManifest: Codable, Sendable {
    struct Entry: Codable, Sendable {
        /// A random on-disk file name — never derived from the logical path.
        let onDiskName: String
        /// The salt this entry's per-file data key was derived from (HKDF over the vault master
        /// key). Not secret on its own: useless without the master key.
        let keySalt: Data
    }

    var entries: [String: Entry] = [:]
}
