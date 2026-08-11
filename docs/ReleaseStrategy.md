# Release Strategy

BlurSecurity releases are boring by design: strictly semantic, humanly reviewed, cryptographically signed, and documented before they ship. Trust compounds through uneventful releases.

## 1. Semantic Versioning — with a security framework's teeth

One version for the whole ecosystem ([ADR-0001](adr/0001-modular-package-ecosystem.md)).

- **Major (X.0.0):** any source-breaking change to public API, a platform-floor raise beyond the support window, or a *default-behavior* change — in this project, tightening a security default is still a major if it can break builds or flows, because surprise is the enemy even when the surprise is good for you. Majors ship with a migration guide during the RC window ([DocumentationStrategy §4](DocumentationStrategy.md)).
- **Minor (x.Y.0):** additive API, new modules (as re-export additions), platform-floor raises within policy, deprecations (with `renamed:` fix-its where mechanical).
- **Patch (x.y.Z):** fixes only. **Security fixes ship as patches on every supported minor**, never bundled with features — an app must be able to take a security fix with zero other diff.

**API stability tiers:**
- Stable: everything public and un-annotated. Covered by the breakage gate from 1.0 onward.
- `@_spi(Experimental)`: real API shipping for feedback, excluded from semver promises, documented as such. Graduation to stable requires the API review checklist re-run and a maintainer second.
- Pre-1.0: 0.x minors may break API, each break listed in the changelog with migration notes. We behave as if stable from 0.5 to practice the discipline before it binds us.

## 2. Cadence & Support Window

- Minors roughly every 8–12 weeks (readiness over calendar); patches on demand; security patches with priority ([SECURITY.md](../SECURITY.md) defines targets).
- **Supported for security fixes:** the latest minor of the current major, and the final minor of the previous major for **18 months** after the major's release. Regulated-industry adopters get a predictable window; we get a bounded backport surface. An LTS designation beyond this is a 2.0-era decision ([MaintenanceStrategy](MaintenanceStrategy.md)).

## 3. The Release Process

1. **Freeze:** release branch cut (`release/x.y`); only fixes land.
2. **Verify:** full release-gate suite ([CICDStrategy](CICDStrategy.md)) — device farm, extended fuzzing, benchmarks, format-compatibility, API-diff review.
3. **Document:** changelog finalized (Keep-a-Changelog format; every entry links its PR; security-relevant changes flagged); DocC published; migration notes if any deprecation shipped.
4. **Review:** a maintainer other than the release driver signs off on the diff-since-last-release summary — a human reads what we're about to ship, every time.
5. **Ship:** signed annotated tag (`vX.Y.Z`) by a maintainer release key; `release.yml` verifies the signature, publishes docs and the GitHub Release.
6. **Announce:** release notes lead with security-relevant changes, then API changes, then the benchmark summary.

Release credentials: tag-signing keys are per-maintainer hardware-backed keys; the set of valid release keys is published in the repository so anyone can verify provenance.

## 4. Deprecation Policy

- Deprecate in a minor with a working replacement and a fix-it; remove no earlier than the *next major*; minimum 12 months between deprecation and removal.
- Security-motivated deprecations (an API pattern we now consider unsafe) may compress this timeline — flagged loudly, with the reasoning published as an ADR, and the unsafe API gains a runtime `SecurityEvent` warning in the interim.

## 5. Changelog Discipline

`CHANGELOG.md` is written *with* the PR, not reconstructed at release time — a PR that changes observable behavior without a changelog entry fails review. Categories: `Security`, `Added`, `Changed`, `Deprecated`, `Fixed`. The `Security` section is never empty-by-omission: if a release contains no security changes, it says so explicitly, because auditors read this file.
