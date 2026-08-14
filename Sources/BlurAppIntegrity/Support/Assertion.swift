import Foundation

/// Per-request proof of key possession.
public struct Assertion: Sendable {
    public let keyID: String
    /// The CBOR assertion object (signature + Apple's monotonic counter); opaque here, verified
    /// server-side.
    public let assertionObject: Data

    /// A stable, versioned envelope — `[version][keyID length][keyID]‖assertionObject` — so
    /// client and server share one framing instead of inventing ad-hoc header schemes. The
    /// server-side guide parses exactly this.
    public var wireRepresentation: Data {
        var out = Data([Assertion.currentVersion])
        let keyIDBytes = Data(keyID.utf8)
        out.append(contentsOf: withUnsafeBytes(of: UInt16(keyIDBytes.count).bigEndian) { Data($0) })
        out.append(keyIDBytes)
        out.append(assertionObject)
        return out
    }

    private static let currentVersion: UInt8 = 1
}
