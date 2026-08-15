# BolourSecurityIntegrationApp

A small SwiftUI app that runs real `BolourSecurity` APIs against a real device or simulator and
shows the actual result — success, a typed error, or an honest "unsupported" — instead of a
scripted double. The practical half of
[docs/IntegrationTesting.md](../docs/IntegrationTesting.md): that doc explains what's automated
and what isn't; this app is where you go to watch the "what isn't" parts run.

Also the first real external consumer of the umbrella product — `import BolourSecurity` here
exercises the `@_exported import` re-export
([ADR-0008](../docs/adr/0008-exported-import-for-umbrella-reexport.md)) end to end, not just
in-tree.

## v1 scope: simulator-only, no team baked in

Public repo — no `DEVELOPMENT_TEAM` set, `CODE_SIGN_STYLE: Automatic`. Every developer signs
with their own Apple ID. Simulator builds need no team at all ("Sign to Run Locally").

| Screen | Needs | What v1 shows |
|---|---|---|
| Keychain | Nothing | Real `SecItem*` round-trip |
| Secure Enclave | Nothing (device or Simulator) | Real key create/sign/verify/destroy |
| Biometrics | Nothing (Simulator can fake enrollment) | Live availability + a real prompt if enrolled |
| App Attest | A real device + your own Team ID + capability | Honestly reports `unsupported(.simulator)` until you add both |
| OAuth Sign-In | A real OAuth client | Disabled until you fill in `OAuthDemoConfiguration` |

### A finding worth flagging

In Simulator, `SecureEnclaveKey.create(tag:)` **succeeds** — it doesn't throw
`errSecMissingEntitlement` the way the bare `swift test` host process does (see
`SecureEnclaveProbe`'s doc comment in the main test suite). A real, signed `.app` bundle gets a
more permissive Simulator path than an unentitled test binary. **This doesn't mean Simulator has
a real Secure Enclave** — there's no hardware to back the key. A successful create/sign/verify
cycle here proves the code path works, never the hardware guarantee. Only a real device proves
that.

## Running it

```bash
brew install xcodegen   # if you don't already have it
cd BolourSecurityIntegrationApp
xcodegen generate       # produces the .xcodeproj — not committed, project.yml is the source of truth
open BolourSecurityIntegrationApp.xcodeproj
```

Build and run on any iOS Simulator. No signing prompts.

## Testing on a real device

1. In Xcode, Signing & Capabilities, pick your own team.
2. For App Attest: change `PRODUCT_BUNDLE_IDENTIFIER` in `project.yml` away from the
   `com.ariabolour.*` placeholder, register that App ID with the App Attest capability in the
   Apple Developer portal, then `xcodegen generate` again.
3. Build and run on the device. App Attest's "Support" line should now read `.supported`.

## Testing OAuth sign-in

Edit `Sources/OAuthValidationView.swift`'s `OAuthDemoConfiguration` with a real client's
`clientID`, `authorizationEndpoint`, `tokenEndpoint`, `redirectURI`. A custom-scheme redirect
URI also needs that scheme under `CFBundleURLTypes` in `project.yml`, then regenerate.

## What this app is not

Not a replacement for the device-required test tiers in
[docs/IntegrationTesting.md](../docs/IntegrationTesting.md), and not the polished
`BolourSecurityDemo` scoped in [ROADMAP.md's 1.0 gate](../ROADMAP.md#whats-required-before-100)
— that's separate, larger, and still unbuilt. This app's only job is letting you see each
hardware/entitlement-gated API actually run.
