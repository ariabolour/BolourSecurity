# Integration & Device Testing

Companion to [TestingStrategy.md](TestingStrategy.md)'s tier design: what actually runs today,
what's tagged but not device-executed, what has no automated test at all, and how to run each
category yourself. See also the [module maturity table](../README.md#module-maturity) and the
[1.0 gate checklist](../ROADMAP.md#whats-required-before-100).

## The three tiers, as they actually exist right now

### Tier 1 — Simulator/host-safe (every PR, every platform in the CI matrix)

Everything not listed below: policy mappings, parsers, state machines exercised against
scripted test doubles (`AppAttestServicing`, `PolicyEvaluating`,
`AuthorizationSessionPresenting`, etc.). The vast majority of the suite — 245 tests, 46 suites
as of this writing, all green on macOS on every PR.

`BolourBiometrics`, `BolourAppIntegrity`, and `BolourOAuth`'s suites are entirely Tier 1 today —
`BiometricAuthenticatorTests`, `AttestationServiceTests`, and `OAuthClientTests` run exclusively
against scripted doubles. There is no real-`LAContext`, real-`DCAppAttestService`, or
real-`ASWebAuthenticationSession` automated test in this repository at all, gated or otherwise —
see the manual checklist below for how that gap is covered in the meantime.

### Tier 2 — Real backend, still host-runnable (every PR, macOS + simulator)

Real OS backends a plain macOS/simulator process can reach: `SecTrust` against generated test
CAs, an in-process TLS harness, an in-process local IdP. Hermetic — nothing reaches the real
network.

"A plain process can reach them" holds on any host with a normal login session, but not
everywhere. `SecTrust` needs `trustd`; `SecPKCS12Import` writes through the **default keychain**
on macOS, and there is no keychain-free route to a `SecIdentity` there
(`SecIdentityCreateWithCertificate` wants the private key in a keychain already, and creating a
scratch legacy keychain is both deprecated and worse — it prompts a GUI dialog on key use, which
hangs an unattended run). A headless container or a sandbox without Mach access to the Security
daemons therefore fails these for reasons that have nothing to do with this package's code:

| Suite | Target | Probe | Symptom where the subsystem is unreachable |
|---|---|---|---|
| `Trust evaluation` | `BolourCertificatesTests` | `SystemTrustProbe.isAvailable` | Happy paths fail with `errSecInternal` (-26276); the fail-closed tests "pass" without evaluating anything |
| `In-process TLS harness` | `BolourNetworkSecurityTests` | `NetworkFixtures.isAvailable` | `SecPKCS12Import` returns `errSecNoDefaultKeychain` (-25307) |

Both carry `Tag.requiresSecurityServices` (declared per-target in `SecurityServicesTestTags.swift`)
and skip rather than fail there. Two properties keep that gate from hiding real bugs:

- **The probes discriminate by cause, not by outcome.** They classify the failure status:
  infrastructure-class (`-26276`, `errSecNoDefaultKeychain`, `errSecNotAvailable`,
  `errSecInteractionNotAllowed`, `errSecServiceNotAvailable`, `errSecMissingEntitlement`) skips;
  anything else — a corrupt fixture, a wrong passphrase, a genuine `TrustEvaluator` regression —
  runs the suite so it fails properly. `SystemTrustProbe` calls the Security APIs directly rather
  than through `TrustEvaluator`, so a regression in our own code can never skip the suite that
  would have caught it.
- **The fail-closed tests assert which failure occurred.** A pin test that accepts any
  `CertificateError` passes on a host where system trust rejects every chain before pinning is
  consulted. They now require `pinMismatch`/`pinSetExpired` specifically, and re-check the
  infrastructure classification per test in case the environment changes mid-run.

None of this is hypothetical. Both failures have been observed, and neither was a code defect;
worse, `NetworkFixtures` used to trap with `fatalError` on an unimportable fixture, taking the
whole test binary down with it so every unrelated suite in that target disappeared too. That
trap is now a thrown, classified error.

### Tier 3 — Device-required (tagged `.requiresDevice`; no CI lane executes it yet)

Three suites exercise a real OS security backend, gated behind a runtime probe
(`KeychainProbe.isAvailable`, `SecureEnclaveProbe.isAvailable`) so they skip cleanly rather than
hang where the backend is unreachable:

| Suite | Target | Backend | Why it's gated |
|---|---|---|---|
| `Keychain integration` | `BolourKeychainTests` | Real `SecItem*` calls | `swift test` and simulator `xctest` both run unentitled — `errSecMissingEntitlement` (-34018) regardless of the hardware |
| `SecureEnclaveKey` | `BolourCryptoTests` | Real Secure Enclave | Same constraint; `kSecAttrTokenIDSecureEnclave` needs a real, provisioned host |
| `TokenStore` | `BolourSecureStorageTests` | Real `SecItem*` calls (via `BolourKeychain`) | Same as `Keychain integration` |

All three carry `Tag.requiresDevice` (declared per-target in `DeviceTestTags.swift`, since this
package has no shared test-support target) — distinct from Tier 2's `.requiresSecurityServices`,
which marks suites that *should* run on any ordinary host and are gated only against the
environments where the Security subsystem is missing. One caveat: `swift test`'s `--filter`/`--skip`
match on test/suite *name* via regex, not on tags — there's no `--filter-tag` in the current
toolchain. The tag is for Xcode's test-plan UI (the actual mechanism a device-hosted run would
use) and as greppable documentation, not for `swift test` itself.

**Bottom line:** these three suites run — and pass — only wherever their probe happens to
succeed (in practice, local dev machines; CI runners return `errSecMissingEntitlement` and skip
them). No CI lane runs them today, and running them meaningfully needs an entitled, app-hosted
test process — a plain `xctest` bundle can't get the entitlement regardless of the hardware
underneath it.

## Entitlement-required (no automated test exists yet)

Real Face ID/Touch ID/Optic ID prompts, real App Attest, and real `ASWebAuthenticationSession`
UI can't be driven from an unattended, unentitled process at all — not gated, genuinely
untestable that way without an actual app target holding the relevant entitlements, running on
real hardware with a human present. `BolourSecurityIntegrationApp` v1
([README](../BolourSecurityIntegrationApp/README.md)) is that app target — simulator-scope by
default, add your own Team ID for the entitled paths. It doesn't run automatically in CI yet —
see the [1.0 gate checklist](../ROADMAP.md#whats-required-before-100).

## Manual verification checklist

`BolourSecurityIntegrationApp` v1 gives you a tappable screen for the Keychain, Secure Enclave,
Biometrics, and App Attest items below instead of writing throwaway code yourself — it doesn't
replace the checklist's judgment calls (what the system UI should look like, what "invisible on
an always-unlocked CI runner" means), just the boilerplate of getting to them.

- **Face ID / Touch ID / Optic ID:** call `BiometricAuthenticator().authenticate(reason:)` on a
  real device with biometry enrolled; confirm the right system UI appears, passcode fallback
  works, and cancellation surfaces as the documented error, not a hang or crash.
- **Secure Enclave:** on a real device or Apple-silicon/T2 Mac, `create(tag:)`, sign, verify,
  `load(tag:)` after a relaunch (confirms persistence), then `destroy()` and confirm a
  subsequent `load` returns `nil`. On a Mac without an SE, confirm `create` throws
  `.secureEnclaveUnavailable` rather than silently falling back.
- **Keychain accessibility classes:** store an item with each `ProtectionPolicy`, lock the
  device, and confirm `.whenUnlockedThisDeviceOnly` items become unreadable while
  `.afterFirstUnlock` items stay readable — invisible on an always-unlocked CI runner.
- **App Attest:** register a real bundle ID, run the full `attestKey`/`assertion` lifecycle
  against Apple's development environment, verify server-side (see
  [BolourAppIntegrity's client-vs-server table](modules/BolourAppIntegrity.md)).
- **`ASWebAuthenticationSession`:** run a real OAuth sign-in on-device — system web-auth UI,
  `state`/PKCE round-trip, `prefersEphemeralSession` behavior.

## Future device-farm strategy

No device farm exists today. Candidates, unevaluated:

- **Xcode Cloud device testing** — native to the toolchain already in `pr.yml`; needs a paid
  plan for real device allocations.
- **A self-hosted Mac-mini + iPhone/iPad pool** — full control, at the cost of running physical
  infrastructure.
- **A commercial device farm** (AWS Device Farm, BrowserStack App Live, Firebase Test Lab) —
  fastest to stand up, least control over device/OS combinations.

Whichever is chosen, the bar is the same: Tier 3's three suites actually running (not just
compiling) against real hardware in CI, plus `BolourSecurityIntegrationApp` covering the
entitlement-required paths this document currently marks manual-only.
