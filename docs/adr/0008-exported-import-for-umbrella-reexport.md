# ADR-0008: `@_exported import` for the umbrella product's re-exports

- **Status:** Accepted
- **Date:** 2026-08-15
- **Deciders:** founding maintainer
- **Security impact:** None — affects symbol visibility under a single `import`, not compiled behavior or runtime security properties

## Context

`BolourSecurity`, the umbrella product, exists so an app that wants the whole platform can write
one `import BolourSecurity` instead of ten. Swift has no public, stable feature for "re-export
everything this module imports" — the only mechanism that does it is `@_exported import`, an
underscored attribute. A leading underscore is Swift's own convention for "ships with the
compiler, not committed to by Swift Evolution."

`Sources/BolourSecurity/BolourSecurity.swift`:

```swift
@_exported import BolourSecurityCore
@_exported import BolourCrypto
// … one per module
```

The dependency was never a secret — anyone reading the umbrella file sees it. This ADR exists
so the *decision* to accept it is a findable record, not just an implicit fact a contributor has
to notice on their own.

## Decision

**Keep `@_exported import`.** Precedented, not novel: Apple's own `swift-collections` and
`swift-algorithms` packages use it for the same purpose. It compiles under every Swift toolchain
this package targets (6.0+), and its failure mode if a future toolchain changed it is a loud
compile error at the umbrella target only — every individual module product is unaffected, since
none of them use the attribute themselves.

## Alternatives Considered

- **Manual re-export of every public symbol.** Avoids the underscore, but trades a
  zero-maintenance umbrella for one that silently drifts — nothing forces a contributor adding a
  new public API to remember the matching re-export line, so `import BolourKeychain` and
  `import BolourSecurity` could quietly expose different surfaces. Rejected: drift risk is worse
  than the underscore.
- **No umbrella product at all.** Considered and rejected — "import one, or import them all" is
  part of this package's stated positioning, not an implementation detail to drop.
- **Accept it, document the decision.** Chosen, for the reasons above.

## Consequences

- Easier: zero umbrella maintenance as modules grow — every new public symbol is automatically
  visible under `import BolourSecurity`.
- Harder: the umbrella build depends on compiler behavior outside Swift's stability guarantees —
  a real dependency, not a hypothetical one.
- Migration: if `@_exported import` ever broke, only `BolourSecurity.swift` needs rework — no
  other target's public API changes.
- **Security:** none identified. Compile-time symbol visibility only; no runtime behavior, no
  security-sensitive code path, and its only failure mode is a compile error, not a silent
  regression.

## Revisit When

Swift ships a stable, non-underscored re-export mechanism, or a toolchain upgrade actually
breaks `@_exported import`'s current behavior.
