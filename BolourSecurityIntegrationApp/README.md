# BolourSecurityIntegrationApp

A small SwiftUI app that exercises real `BolourSecurity` APIs against a real iOS
device/simulator and shows the actual result — success, a typed error, or an honest
"unsupported" — instead of a scripted test double. It's the practical half of
[docs/IntegrationTesting.md](../docs/IntegrationTesting.md): that document explains what's
automated and what isn't; this app is where you go to see the "what isn't" parts run for real.

It's also the first real external consumer of the `BolourSecurity` umbrella product —
`import BolourSecurity` here is what actually exercises the `@_exported import` re-export
mechanism [ADR-0008](../docs/adr/0008-exported-import-for-umbrella-reexport.md) documents,
end to end, not just in-tree.

## v1 scope: simulator-only, no team baked in

This is a public repository. The project is deliberately configured with **no
`DEVELOPMENT_TEAM`** and **`CODE_SIGN_STYLE: Automatic`** — every developer who runs it signs
with their own Apple ID, not one that happened to be on the machine that wrote this app.
Simulator builds need no team at all (`codesign --sign -`, "Sign to Run Locally"). Five
screens are included:

| Screen | Needs | What v1 actually shows |
|---|---|---|
| Keychain | Nothing | Real `SecItem*` round-trip |
| Secure Enclave | Nothing (device or Simulator) | Real key create/sign/verify/destroy |
| Biometrics | Nothing (Simulator can fake enrollment) | Live availability + a real prompt if enrolled |
| App Attest | A real device + your own Team ID + capability | Honestly reports `unsupported(.simulator)` until you add both |
| OAuth Sign-In | A real OAuth client | Disabled until you fill in `OAuthDemoConfiguration` |

### A finding worth flagging

Running this app in Simulator, `SecureEnclaveKey.create(tag:)` **succeeds** — it does not throw
`errSecMissingEntitlement` the way the bare `swift test` host process does (see
`SecureEnclaveProbe`'s doc comment in the main package's test suite, which documents exactly
that failure for an *unentitled test binary*). A real, code-signed `.app` bundle apparently gets
a different, more permissive path in Simulator than a raw `xctest` host does. **This does not
mean Simulator has a real Secure Enclave** — it has none; there is no hardware SE to back the
key. Treat a "successful" create/sign/verify cycle in Simulator as proof the *code path* works,
never as proof of the *hardware security property* `SecureEnclaveKey` exists to provide. Only a
real device confirms that.

## Running it

```bash
brew install xcodegen   # if you don't already have it
cd BolourSecurityIntegrationApp
xcodegen generate       # produces BolourSecurityIntegrationApp.xcodeproj — not committed;
                         # project.yml is the source of truth, regenerate after editing it
open BolourSecurityIntegrationApp.xcodeproj
```

Build and run on any iOS Simulator. No signing prompts should appear.

## Testing on a real device

1. Open the generated project in Xcode, select the `BolourSecurityIntegrationApp` target,
   Signing & Capabilities, and pick your own personal or organization team.
2. For App Attest specifically: register an App ID matching whatever bundle identifier you're
   using (change `PRODUCT_BUNDLE_IDENTIFIER` in `project.yml` away from the
   `com.ariabolour.*` placeholder first), enable the App Attest capability on it in the Apple
   Developer portal, then re-run `xcodegen generate`.
3. Build and run on the physical device. The App Attest screen's "Support" line should now read
   `.supported` instead of `.unsupported(.simulator)`.

## Testing OAuth sign-in

Edit `Sources/OAuthValidationView.swift`'s `OAuthDemoConfiguration` with a real OAuth client's
`clientID`, `authorizationEndpoint`, `tokenEndpoint`, and `redirectURI`. If your redirect URI
uses a custom URL scheme (the common case for a native app), also add that scheme under
`CFBundleURLTypes` in `project.yml`'s `settings`, then `xcodegen generate` again.

## What this app is not

It's not a replacement for the device-required automated test tiers described in
[docs/IntegrationTesting.md](../docs/IntegrationTesting.md), and it doesn't attempt anything
close to the full "polished demo" scope described for `BolourSecurityDemo` in
[ROADMAP.md's 1.0 gate](../ROADMAP.md#whats-required-before-100) — that's a separate,
larger, still-unbuilt piece of work. This app's only job is letting you *see* each
hardware/entitlement-gated API actually run, honestly, on whatever you have in front of you.
