import Testing

/// Test-tier vocabulary shared across this target — see `docs/IntegrationTesting.md`.
/// Declared per-target (Swift Testing tags are compared by declaration identity, and this
/// package has no shared test-support target yet); the *name* is what matters for Xcode test
/// plan selection and for a human reading test output, and is kept identical across every
/// target that declares it.
extension Tag {
    /// Marks a suite whose tests exercise a real OS/hardware backend (live keychain, Secure
    /// Enclave, biometric prompt, App Attest) rather than a scripted test double. Such suites
    /// typically also carry a runtime `.enabled(if:)` probe so they skip cleanly on an
    /// unentitled host — the tag is a declarative, greppable marker of *why*, and the seam a
    /// future device-hosted test plan selects on.
    @Tag static var requiresDevice: Tag
}
