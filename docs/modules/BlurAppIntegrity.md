# BlurAppIntegrity

**Layer 3 · Protocols & Services.** App Attest and DeviceCheck as one lifecycle, not two APIs.

## Mission

Answer the product question — *"is this request coming from a legitimate build of my app on a real Apple device?"* — by managing the full App Attest lifecycle (key generation, attestation, assertion, invalidation recovery) and DeviceCheck token issuance behind one service, with the state machine that Apple's raw APIs leave as an exercise for the reader. App Attest and DeviceCheck ship together because they answer the same question at different assurance levels ([ADR-0005](../adr/0005-consolidated-module-set.md)).

## Responsibilities

- App Attest: SE-resident key generation, one-time attestation against a server challenge, per-request assertions, counter management, and recovery when keys are invalidated (device restore, app reinstall).
- DeviceCheck: ephemeral device-token generation for server-side bit queries and fraud signals.
- Persistent, keychain-backed state (key IDs, attestation status) so the lifecycle survives launches without app bookkeeping.
- The `AttestationProviding` seam conformance, so an app's networking layer can demand assertions without importing this module's internals.
- Server-side verification *documentation and test vectors* — protocol spelled out; implementation out of scope ([Architecture.md §9](../Architecture.md)).

## Public API (signature-level design)

```swift
public actor AttestationService: AttestationProviding {
    public init(keychain: Keychain = Keychain(),
                logger: (any SecurityEventLogger)? = nil)

    /// Whether this device/build can attest (simulators, some Macs, unsupported OSes cannot).
    public nonisolated var support: AttestationSupport { get }

    /// One-time (per key) attestation. Generates the SE key if needed, attests it
    /// against the server-issued challenge, persists state, returns the material
    /// the server verifies against Apple.
    public func attestKey(challenge: ServerChallenge) async throws(IntegrityError) -> Attestation

    /// Per-request proof. `clientData` is typically a hash of the request body + a
    /// server nonce. Throws `.keyNotAttested` before first attestation, and
    /// `.keyInvalidated` when the OS revoked the key — both with a documented,
    /// typed recovery path (re-attest).
    public func assertion(for clientData: ClientData) async throws(IntegrityError) -> Assertion

    /// Tears down local state after server-coordinated re-enrollment.
    public func resetAttestation() async throws(IntegrityError)
}

public struct ServerChallenge: Sendable {                 // server-minted nonce, opaque here
    public init(_ data: Data)
}
public struct ClientData: Sendable {
    public init(hashing requestBody: some DataProtocol, serverNonce: Data)
    public init(precomputedHash: Digest256)
}

public struct Attestation: Sendable {
    public var keyID: String { get }
    public var attestationObject: Data { get }            // CBOR blob the server sends to Apple's chain
}
public struct Assertion: Sendable {
    public var keyID: String { get }
    public var assertionObject: Data { get }
    public var wireRepresentation: Data { get }           // stable envelope: keyID + assertion, versioned
}

public enum AttestationSupport: Sendable {
    case supported
    case unsupported(reason: UnsupportedReason)           // .simulator, .platform, .managedDevice…
}

// MARK: DeviceCheck (lower-assurance sibling)
public enum DeviceCheckToken {
    /// Ephemeral token for the server-side DeviceCheck query/update API.
    public static func generate() async throws(IntegrityError) -> Data
    public static var isSupported: Bool { get }
}

public enum IntegrityError: SecurityError {
    case unsupported(UnsupportedReason)
    case keyNotAttested                                   // recovery: attestKey(challenge:)
    case keyInvalidated                                   // OS revoked (restore/reinstall); recovery: reset + re-attest
    case attestationRejected(underlying: any Error & Sendable)
    case serverChallengeRequired                          // structural misuse caught with a teaching error
    case rateLimited(retryAfter: Duration?)
    case underlying(any Error & Sendable)
}
```

## Dependencies

`BlurSecurityCore`, `BlurCrypto` (hashing for `ClientData`), `BlurKeychain` (state persistence); Apple: DeviceCheck (`DCAppAttestService`, `DCDevice`), Foundation.

## Architecture

- **The state machine is the product.** Internal states — `noKey → keyGenerated → attested`, with `invalidated` reachable from any state — are persisted via `BlurKeychain` (`.afterFirstUnlock()`, device-only: assertions must work on background refresh, and attest keys must never sync). `AttestationService` is one of the three sanctioned actors; all transitions serialize through it, so double-generation and attest/assert races are structurally gone.
- `assertion(for:)` computes the client-data hash via `BlurCrypto.SHA256` and increments Apple's monotonic counter semantics; the service surfaces counter anomalies as `keyInvalidated`-class signals rather than letting servers discover drift.
- `wireRepresentation` gives teams a stable, versioned envelope so client and server don't invent ad-hoc framing — the docs' server-side guide parses exactly this envelope.
- **Server-side guide** (DocC article + fixtures): verifying the attestation object against Apple's App Attest root CA, checking `rpID`/bundle hash, environment (development vs production) handling, counter tracking, challenge freshness. Ships with golden attestation/assertion fixtures for server test suites.

## Usage Examples

```swift
import BlurAppIntegrity

let integrity = AttestationService()

// First run: one-time enrollment
if case .supported = integrity.support {
    let challenge = try await api.fetchAttestationChallenge()
    let attestation = try await integrity.attestKey(challenge: ServerChallenge(challenge))
    try await api.enroll(attestation.attestationObject, keyID: attestation.keyID)
}

// Every sensitive request: attach proof
let assertion = try await integrity.assertion(
    for: ClientData(hashing: requestBody, serverNonce: nonce)
)
request.setValue(assertion.wireRepresentation.base64EncodedString(),
                 forHTTPHeaderField: "X-App-Assertion")
```

## Testing Strategy

- `DCAppAttestService` sits behind an internal protocol; scripted doubles drive **every** state-machine transition and every `DCError` → `IntegrityError` mapping as table-driven tests, including the invalidation-mid-flight paths that are nearly impossible to reproduce on hardware.
- Persistence tests: state round-trips through the keychain double; simulated app-relaunch (fresh actor, same store) resumes the correct state.
- Device CI (tagged `.requiresDevice` + `.requiresAppAttestEntitlement`): real key generation and assertion against Apple's development environment; attestation-object structure golden-checked.
- Simulator CI asserts the honest path: `support == .unsupported(.simulator)` and typed errors — never a crash, never a hang.
- Fixture generation script (device-run) refreshes server-side golden vectors each release.

## Security Considerations & Common Mistakes Prevented

- **Prevented: attest-once-and-trust-forever** — the lifecycle surfaces invalidation as a first-class typed state with a recovery protocol, instead of the silent 4xx loop teams usually ship.
- **Prevented: client-minted challenges** — `ServerChallenge` exists to make "I hashed my own timestamp" visibly wrong; `serverChallengeRequired` catches the structural misuse with a teaching error.
- **Prevented: assertion replay framing bugs** — `ClientData(hashing:serverNonce:)` bakes the server nonce into the hash; the server guide verifies it.
- **Prevented: attest keys in synced/backup scopes** — persistence policy is fixed device-only; there is no parameter to get this wrong.
- **Honest limits (stated loudly in docs):** App Attest raises the cost of abuse; it is not DRM, not jailbreak detection, and a compromised OS can lie in bounded ways. DeviceCheck's two bits are a fraud signal, not an identity. Server-side verification is *mandatory* — an unverified attestation is theater, and the docs refuse to let teams believe otherwise.

## Future Roadmap

- Risk-signal aggregation seam (attestation state × BiometryState × policy) for fraud teams (v2.x, own ADR — scope creep risk is real here).
- DPoP-style binding of assertions to OAuth tokens, with BlurJWT (v2.x).
- Managed-device (MDM) posture notes and enterprise attestation patterns article (v1.x).
- Watch for App Attest API evolution (e.g. macOS expansion) — same-release support per MaintenanceStrategy.
