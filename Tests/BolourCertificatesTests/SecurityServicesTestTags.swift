import Testing

/// Test-tier vocabulary shared across this target — see `docs/IntegrationTesting.md`.
/// Declared per-target (Swift Testing tags are compared by declaration identity, and this
/// package has no shared test-support target); the *name* is what matters for Xcode test plan
/// selection and for a human reading test output, and is kept identical across every target
/// that declares it.
extension Tag {
    /// Marks a Tier-2 suite: it needs a working platform Security subsystem (`trustd` for
    /// `SecTrust`, a usable default keychain for `SecPKCS12Import`) but no entitlement and no
    /// real hardware, so an ordinary macOS or simulator process runs it on every PR.
    ///
    /// Distinct from `.requiresDevice`, which marks Tier 3 — suites that need an *entitled*
    /// host or genuine hardware and cannot pass under `swift test` at all. A
    /// `.requiresSecurityServices` suite is expected to run everywhere a developer or CI runner
    /// has a normal login session; the accompanying `.enabled(if:)` probe exists for the
    /// environments that don't (headless containers, sandboxes with no Mach access to the
    /// Security daemons), where the alternative is a wall of failures that look like code bugs.
    @Tag static var requiresSecurityServices: Tag
}
