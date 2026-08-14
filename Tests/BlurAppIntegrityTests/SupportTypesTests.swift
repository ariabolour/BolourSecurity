import Testing
import Foundation
import BlurCrypto
@testable import BlurAppIntegrity

@Suite("ClientData")
struct ClientDataTests {
    @Test("hashing(requestBody:serverNonce:) hashes the concatenation of body and nonce")
    func hashesConcatenation() {
        let body = Data("body".utf8)
        let nonce = Data("nonce".utf8)
        let clientData = ClientData(hashing: body, serverNonce: nonce)
        let expected = SHA256.digest(of: body + nonce)
        #expect(clientData.hashData == expected.withUnsafeBytes { Data($0) })
    }

    @Test("precomputedHash is used as-is")
    func precomputedHashUsedAsIs() {
        let digest = SHA256.digest(of: Data("anything".utf8))
        let clientData = ClientData(precomputedHash: digest)
        #expect(clientData.hashData == digest.withUnsafeBytes { Data($0) })
    }
}

@Suite("Assertion wireRepresentation")
struct AssertionWireRepresentationTests {
    @Test("encodes version, keyID length, keyID, and the assertion object in order")
    func encodesFieldsInOrder() {
        let assertion = Assertion(keyID: "abc", assertionObject: Data([0xAA, 0xBB]))
        let wire = assertion.wireRepresentation
        #expect(wire[wire.startIndex] == 1)
        let keyIDLength = UInt16(wire[wire.startIndex + 1]) << 8 | UInt16(wire[wire.startIndex + 2])
        #expect(keyIDLength == 3)
        let keyIDBytes = wire.subdata(in: (wire.startIndex + 3)..<(wire.startIndex + 3 + 3))
        #expect(String(decoding: keyIDBytes, as: UTF8.self) == "abc")
        #expect(wire.suffix(2) == Data([0xAA, 0xBB]))
    }
}

@Suite("AttestationState")
struct AttestationStateTests {
    @Test(
        "round-trips through SecretConvertible for every case",
        arguments: [
            AttestationState.noKey,
            .keyGenerated(keyID: "k1"),
            .attested(keyID: "k2"),
            .invalidated(keyID: "k3"),
            .invalidated(keyID: nil),
        ]
    )
    func roundTrips(_ state: AttestationState) throws {
        let bytes = try state.secureBytesRepresentation()
        let restored = try AttestationState(secureBytes: bytes)
        #expect(restored == state)
    }
}
