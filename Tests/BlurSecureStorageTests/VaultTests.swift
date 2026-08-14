import Testing
import Foundation
@testable import BlurSecureStorage
import BlurSecurityCore
import BlurCrypto

@Suite("Vault")
struct VaultTests {

    private func makeVault(masterKeyBytes: SecureBytes? = nil) throws -> (vault: Vault, directory: URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("VaultTests-\(UUID().uuidString)", isDirectory: true)
        let vault = try Vault.openForTesting(
            directoryURL: directory, masterKeyBytes: masterKeyBytes ?? SecureRandom.bytes(count: 32)
        )
        return (vault, directory)
    }

    // MARK: - Round trip

    @Test("write then read round-trips the exact bytes")
    func roundTrip() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        let payload = Data("hello vault".utf8)
        try await vault.write(payload, to: "notes.txt")
        #expect(try await vault.read(from: "notes.txt") == payload)
    }

    @Test("empty payloads round-trip")
    func emptyPayload() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await vault.write(Data(), to: "empty.bin")
        #expect(try await vault.read(from: "empty.bin") == Data())
    }

    @Test("reading a path that was never written throws pathNotFound")
    func missingPathThrows() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        await #expect(throws: StorageError.self) {
            _ = try await vault.read(from: "nope.txt")
        }
    }

    @Test("writing to the same path twice replaces the old on-disk artifact")
    func overwriteReplacesOldFile() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await vault.write(Data("v1".utf8), to: "doc.txt")
        try await vault.write(Data("v2".utf8), to: "doc.txt")
        #expect(try await vault.read(from: "doc.txt") == Data("v2".utf8))

        let filesURL = directory.appendingPathComponent("files")
        let onDisk = try FileManager.default.contentsOfDirectory(atPath: filesURL.path)
        #expect(onDisk.count == 1)
    }

    // MARK: - Directory listing & removal

    @Test("contents(of:) lists only the immediate children of a directory")
    func contentsListsImmediateChildren() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await vault.write(Data(), to: "top.txt")
        try await vault.write(Data(), to: "reports/2026-01.pdf")
        try await vault.write(Data(), to: "reports/2026-02.pdf")
        try await vault.write(Data(), to: "reports/nested/deep.pdf")

        // Only paths actually written show up; "reports/..." entries are one level too deep to
        // appear at the root, and there is no synthetic "reports" directory entry.
        let root = try await vault.contents(of: .root)
        #expect(root.map(\.storageKey) == ["top.txt"])

        let reports = try await vault.contents(of: try VaultPath(validating: "reports"))
        #expect(Set(reports.map(\.storageKey)) == ["reports/2026-01.pdf", "reports/2026-02.pdf"])
    }

    @Test("remove deletes the entry and the read afterward throws pathNotFound")
    func removeThenReadThrows() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await vault.write(Data("x".utf8), to: "gone.txt")
        try await vault.remove("gone.txt")
        await #expect(throws: StorageError.self) {
            _ = try await vault.read(from: "gone.txt")
        }
    }

    @Test("remove on a path that was never written throws pathNotFound")
    func removeMissingThrows() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        await #expect(throws: StorageError.self) {
            try await vault.remove("nope.txt")
        }
    }

    // MARK: - Persistence across reopen

    @Test("data written by one Vault instance is visible after reopening the same directory")
    func persistsAcrossReopen() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("VaultTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let masterKey = SecureRandom.bytes(count: 32)

        do {
            let vault = try Vault.openForTesting(directoryURL: directory, masterKeyBytes: masterKey)
            try await vault.write(Data("persisted".utf8), to: "a.txt")
        }
        let reopened = try Vault.openForTesting(directoryURL: directory, masterKeyBytes: masterKey)
        #expect(try await reopened.read(from: "a.txt") == Data("persisted".utf8))
    }

    @Test("opening the same directory with the wrong master key fails closed")
    func wrongMasterKeyFailsClosed() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("VaultTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let vault = try Vault.openForTesting(directoryURL: directory, masterKeyBytes: SecureRandom.bytes(count: 32))
        try await vault.write(Data("secret".utf8), to: "a.txt")

        #expect(throws: StorageError.self) {
            _ = try Vault.openForTesting(directoryURL: directory, masterKeyBytes: SecureRandom.bytes(count: 32))
        }
    }

    // MARK: - Tamper matrix

    @Test("a bit-flip anywhere in a file's sealed body is detected, never returns garbage plaintext",
          arguments: [0, 1, 5, -1])
    func tamperedBodyFailsClosed(offsetFromRelevantEnd: Int) async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await vault.write(Data("authentic content".utf8), to: "doc.txt")
        let filesURL = directory.appendingPathComponent("files")
        let onDiskName = try FileManager.default.contentsOfDirectory(atPath: filesURL.path)[0]
        let fileURL = filesURL.appendingPathComponent(onDiskName)

        try flipBit(at: offsetFromRelevantEnd, in: fileURL)

        await #expect(throws: StorageError.self) {
            _ = try await vault.read(from: "doc.txt")
        }
    }

    @Test("a bit-flip anywhere in the sealed manifest is detected on the next open",
          arguments: [0, 1, 10, -1])
    func tamperedManifestFailsClosed(offsetFromRelevantEnd: Int) async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("VaultTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let masterKey = SecureRandom.bytes(count: 32)

        let vault = try Vault.openForTesting(directoryURL: directory, masterKeyBytes: masterKey)
        try await vault.write(Data("content".utf8), to: "doc.txt")

        let manifestURL = directory.appendingPathComponent("manifest.sealed")
        try flipBit(at: offsetFromRelevantEnd, in: manifestURL)

        #expect(throws: StorageError.self) {
            _ = try Vault.openForTesting(directoryURL: directory, masterKeyBytes: masterKey)
        }
    }

    /// Flips one bit at `offset` bytes from the start (non-negative) or end (negative) of the
    /// file at `url`.
    private func flipBit(at offset: Int, in url: URL) throws {
        var data = try Data(contentsOf: url)
        let index = offset >= 0 ? offset : data.count + offset
        guard data.indices.contains(index) else { return }
        data[index] ^= 0xFF
        try data.write(to: url)
    }

    // MARK: - Simulated interrupted write

    @Test("a truncated on-disk file fails closed without affecting other entries")
    func truncatedFileDoesNotAffectOthers() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await vault.write(Data("first file content".utf8), to: "a.txt")
        try await vault.write(Data("second file content".utf8), to: "b.txt")

        let filesURL = directory.appendingPathComponent("files")
        let entries = try await vault.contents(of: .root)
        #expect(entries.count == 2)

        // Simulate a writer that died partway through, leaving one on-disk file truncated
        // (but non-empty). Which of the two entries it belongs to doesn't matter for the
        // property under test.
        let onDiskNames = try FileManager.default.contentsOfDirectory(atPath: filesURL.path)
        let truncatedURL = filesURL.appendingPathComponent(onDiskNames[0])
        let full = try Data(contentsOf: truncatedURL)
        try full.prefix(full.count / 2).write(to: truncatedURL)

        // Reading the untouched file still succeeds; reading the truncated one fails closed
        // (never crashes, never returns partial/garbage plaintext) — and does not affect the
        // other entry's manifest metadata or on-disk bytes at all.
        var successes = 0
        var failures = 0
        for entry in entries {
            do {
                _ = try await vault.read(from: entry)
                successes += 1
            } catch {
                failures += 1
            }
        }
        #expect(successes == 1)
        #expect(failures == 1)
    }

    // MARK: - Streaming (v0.5: buffered, not constant-memory — see Vault's doc comment)

    @Test("writeStream then readStream round-trips chunked content")
    func streamingRoundTrip() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        let writeStream = try await vault.writeStream(to: "stream.bin")
        await writeStream.write(Data("chunk-one-".utf8))
        await writeStream.write(Data("chunk-two".utf8))
        try await writeStream.finish()

        let readStream = try await vault.readStream(from: "stream.bin")
        var collected = Data()
        while let chunk = await readStream.read(maxLength: 4) {
            collected.append(chunk)
        }
        #expect(collected == Data("chunk-one-chunk-two".utf8))
    }

    // MARK: - Destruction

    @Test("destroyVaultAndAllContents removes the vault directory")
    func destroy() async throws {
        let (vault, directory) = try makeVault()
        try await vault.write(Data("x".utf8), to: "a.txt")
        #expect(FileManager.default.fileExists(atPath: directory.path))
        try await vault.destroyVaultAndAllContents()
        #expect(!FileManager.default.fileExists(atPath: directory.path))
    }

    // MARK: - Concurrency

    @Test("concurrent writes to distinct paths all land correctly")
    func concurrentWritesToDistinctPaths() async throws {
        let (vault, directory) = try makeVault()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<20 {
                group.addTask {
                    try await vault.write(Data("value-\(index)".utf8), to: try VaultPath(validating: "item-\(index).txt"))
                }
            }
            try await group.waitForAll()
        }

        for index in 0..<20 {
            let value = try await vault.read(from: try VaultPath(validating: "item-\(index).txt"))
            #expect(value == Data("value-\(index)".utf8))
        }
    }
}
