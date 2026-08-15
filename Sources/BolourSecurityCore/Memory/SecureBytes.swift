import Foundation

/// A heap buffer for secret material that redacts itself and best-effort-zeroes its
/// storage when the last copy is released.
///
/// `SecureBytes` is the ecosystem's native currency for secrets: keychain payloads,
/// derived keys, decrypted plaintext in flight. It is deliberately **not** `Codable` and
/// never prints its contents. The only way out is ``dangerouslyExportBytes()``, whose name
/// is the warning.
///
/// - Important: **Honest zeroization — read this before treating it as a stronger guarantee
///   than it is.** Swift's ARC and copy-on-write make guaranteed zeroing of *every* copy of a
///   secret impossible in pure Swift. What `SecureBytes` actually does, precisely:
///   - **What is zeroed, and when:** the one heap buffer this value's `Storage` class owns is
///     overwritten with `memset_s` (which the optimizer cannot elide, unlike plain `memset`)
///     in `deinit`, when the last reference to that buffer is released.
///   - **What is *not* covered:** any copy taken out through ``withUnsafeBytes(_:)`` or
///     ``dangerouslyExportBytes()`` is a plain, unmanaged buffer (`Data`, a local `[UInt8]`,
///     a value captured into a closure) that `SecureBytes` has no further reference to and
///     cannot zero. Once secret bytes leave through either API, their lifetime and zeroing
///     are the caller's responsibility.
///   - **Temporary buffers during construction:** `init(_:)` copies its input into an
///     intermediate `Array` before moving it into the owned buffer, and best-effort-zeroes
///     that intermediate array afterward (see the initializer) — but the *original* sequence
///     the caller passed in (e.g. a `String`'s or `Data`'s own backing storage) is never
///     touched, since `SecureBytes` doesn't own it.
///   - **Copy-on-write:** `SecureBytes` itself has no COW storage to worry about (`Storage`
///     is a reference type, written once at `init` and never mutated), but any `Data`/`Array`
///     copy taken via `withUnsafeBytes`/`dangerouslyExportBytes` is fully subject to Swift's
///     normal COW semantics and may be silently duplicated by the runtime.
///   - **Bridging risk:** passing exported bytes into an Objective-C/C API (or storing them in
///     a `String`) can retain further, entirely untracked copies — string interning and small
///     buffer optimizations in particular can leave secret-derived bytes resident in memory
///     regions this type has no visibility into.
///   - **Logging:** never log ``dangerouslyExportBytes()``'s result or any value derived from
///     it. `SecureBytes` itself is safe to log (``description`` is always the redacted form),
///     but that guarantee ends the moment the caller exports.
///   - **Debugger and core-dump limitations:** none of the above defends against a debugger
///     attached to the process, a core dump, or a swap/hibernation file — all can capture the
///     buffer's contents (or a copy of it) while it's live, regardless of what `deinit` does
///     afterward. This type mitigates *lifetime* exposure in normal operation; it is not a
///     defense against a process already under an attacker's control.
///
///   In short: `SecureBytes` reduces the exposure window for the one buffer it owns and
///   controls end-to-end. It does not, and cannot, guarantee that every copy of a secret is
///   erased from every memory location it ever touched.
public struct SecureBytes: Sendable, Hashable, ContiguousBytes {

    /// Reference-typed backing so storage can be wiped in `deinit` (structs have none).
    /// Contents are written only during `init` and wiped only in `deinit`; the buffer is
    /// never mutated in between, so sharing across concurrency domains is safe.
    private final class Storage: @unchecked Sendable {
        let buffer: UnsafeMutableRawBufferPointer

        init(count: Int) {
            precondition(count >= 0, "SecureBytes count must be non-negative")
            buffer = .allocate(byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
            if count > 0, let base = buffer.baseAddress {
                _ = memset(base, 0, count)
            }
        }

        init(bytes: [UInt8]) {
            let count = bytes.count
            buffer = .allocate(byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
            if count > 0 {
                bytes.withUnsafeBytes { source in
                    buffer.copyMemory(from: source)
                }
            }
        }

        deinit {
            let count = buffer.count
            if count > 0, let base = buffer.baseAddress {
                // memset_s is guaranteed not to be optimized away, unlike memset.
                _ = memset_s(base, count, 0, count)
            }
            buffer.deallocate()
        }
    }

    private let storage: Storage

    /// Creates a buffer holding a copy of `bytes`.
    public init(_ bytes: some Sequence<UInt8>) {
        var array = Array(bytes)
        storage = Storage(bytes: array)
        // Best-effort wipe of the temporary copy we just made.
        array.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress, raw.count > 0 {
                _ = memset_s(base, raw.count, 0, raw.count)
            }
        }
    }

    /// Creates a zero-filled buffer of `count` bytes.
    public init(count: Int) {
        storage = Storage(count: count)
    }

    /// The number of bytes held.
    public var count: Int { storage.buffer.count }

    /// Whether the buffer holds no bytes.
    public var isEmpty: Bool { count == 0 }

    /// Calls `body` with a raw pointer to the bytes. The pointer is valid only for the
    /// duration of the call and must not escape it.
    public func withUnsafeBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        try body(UnsafeRawBufferPointer(storage.buffer))
    }

    /// Copies the secret out into a `Data`. Named to read as a deliberate, lossy exit: the
    /// returned bytes are no longer protected or zeroed by `SecureBytes`.
    public func dangerouslyExportBytes() -> Data {
        withUnsafeBytes { Data($0) }
    }
}

extension SecureBytes {
    /// Constant-time equality over the byte contents. A length mismatch (lengths are not
    /// secret) returns `false` immediately; equal-length buffers are compared without an
    /// early exit so timing does not reveal where they differ.
    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        lhs.withUnsafeBytes { l in
            rhs.withUnsafeBytes { r in
                guard l.count == r.count else { return false }
                var difference: UInt8 = 0
                for index in 0..<l.count {
                    difference |= l[index] ^ r[index]
                }
                return difference == 0
            }
        }
    }

    public func hash(into hasher: inout Hasher) {
        withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}

extension SecureBytes: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "SecureBytes(\(count) bytes, redacted)" }
    public var debugDescription: String { description }
}
