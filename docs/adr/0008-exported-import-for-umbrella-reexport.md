# ADR-0008: `@_exported import` for the umbrella product's re-exports

- **Status:** Accepted
- **Date:** 2026-08-15
- **Deciders:** founding maintainer
- **Security impact:** None — this affects symbol visibility under a single `import`, not compiled behavior, type safety, or runtime security properties

## Context

`BolourSecurity`, the umbrella product, exists so an app that wants the whole platform can write one `import BolourSecurity` instead of ten. Swift has no public, stable language feature that means "re-export everything this module imports" — the only mechanism that does it is `@_exported import`, an underscored attribute. By Swift's own naming convention, a leading underscore marks a feature as outside the officially supported, stability-guaranteed language surface: it ships with the compiler, but isn't part of the language the Swift Evolution process has committed to.

`Sources/BolourSecurity/BolourSecurity.swift` currently reads:

```swift
@_exported import BolourSecurityCore
@_exported import BolourCrypto
// … one per module
```

This ADR exists because a package whose whole pitch is architectural rigor and honest documentation shouldn't depend on an underscored compiler feature *silently*. The dependency itself isn't news to anyone who reads the umbrella file — this ADR is about making the *decision* to accept it, and the reasoning behind it, a first-class, findable record instead of an implicit fact a contributor has to notice on their own.

## Decision

**Keep `@_exported import` for the umbrella target's re-exports, with this ADR as the explicit record that the dependency was evaluated and accepted, not overlooked.**

This is a well-precedented pattern, not a novel risk: Apple's own `swift-collections` and `swift-algorithms` packages use `@_exported import` for exactly this umbrella-re-export purpose. It compiles under every Swift toolchain this package targets (Swift 6.0+), and its failure mode if a future toolchain ever changed it is a loud compile error at the umbrella target specifically — every individual module product (`BolourKeychain`, `BolourCrypto`, and so on) is entirely unaffected, since none of them use this attribute themselves.

## Alternatives Considered

- **Manual re-export of every public symbol** (typealiases / forwarding declarations for each type, function, and case across ten modules). Avoids the underscored feature entirely, but trades a zero-maintenance umbrella target for one that silently drifts: nothing forces a contributor adding a new public API to a module to remember the matching manual re-export line in `BolourSecurity.swift`, so `import BolourKeychain` and `import BolourSecurity` could quietly expose different surfaces. The current file's own comment states the property this alternative would give up: "no change to this file is needed when a module fills in." Rejected — the maintenance burden and drift risk are worse than the underscore.
- **No umbrella product at all.** Genuinely the simplest option, and it was considered. Rejected because "import one, or import them all" is a stated part of this package's positioning (README's "A platform, not a wrapper" pillar) — dropping the umbrella changes what BolourSecurity *is*, not just how it's implemented.
- **Accept `@_exported import`, document the decision explicitly.** Chosen. The precedent from Apple's own packages, the narrow and loud (not silent) failure mode, and the alternative's worse maintenance story together make this the right tradeoff — but "the right tradeoff" is exactly the kind of judgment call this project's own discipline says belongs in an ADR, not just in a code comment.

## Consequences

- Easier: the umbrella target needs zero maintenance as modules grow — every new public symbol in any of the ten modules is automatically visible under `import BolourSecurity` with no corresponding edit here.
- Harder: the umbrella product's build depends on compiler behavior outside Swift's stability guarantees. This is a real, if currently low-probability, dependency — not a hypothetical one, since it's an actual underscored feature, not a documented language construct.
- Migration/compatibility: if `@_exported import` were ever removed or changed incompatibly, only `BolourSecurity.swift` needs rework (manual re-exports, or a generated equivalent) — no other target's public API or behavior changes.
- **Security consequences:** none identified. This attribute affects symbol visibility at compile time only; it has no runtime behavior, doesn't touch any security-sensitive code path, and its failure mode (a compile error) can't manifest as a silent security regression.

## Revisit When

Swift ships a stable, non-underscored re-export mechanism (there have been community pitches for one), or a Swift toolchain upgrade actually breaks `@_exported import`'s current behavior — whichever comes first. Until then, this ADR is the record that the tradeoff was made deliberately.
