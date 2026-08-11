# CI/CD Strategy

GitHub Actions, defined here as design; workflow YAML is authored in v0.1 alongside `Package.swift`. Principles: every gate that protects a guarantee runs on every PR; nothing release-critical exists only on a maintainer's laptop; CI is hermetic (no external service dependencies — see [TestingStrategy](TestingStrategy.md)).

## 1. Workflows

**`pr.yml` — every pull request.**
- **Build matrix:** latest stable Xcode across destinations — macOS (arm64), iOS simulator, watchOS simulator, visionOS simulator — in Swift 6 language mode, warnings as errors. A second lane builds against the *previous* Xcode until our support window drops it.
- **Tests:** Tier 1–2 (unit + hermetic integration) on the matrix; TSan lane on modules touched by the diff; Tier 5 negative-compilation fixtures; bounded Tier 4 corpus replay.
- **API integrity:** `swift package diagnose-api-breaking-changes` against the latest release tag — an undeclared public-API break fails the job (declared breaks require the `api-break-approved` label applied by a maintainer, only ever on a major-version branch).
- **Docs:** DocC build with warnings-as-errors + coverage audit (undocumented public symbol = failure) + snippet-extraction compile.
- **Hygiene:** `swift-format` lint (Apple's formatter, invoked as a tool, not a package dependency per [ADR-0002](adr/0002-zero-third-party-dependencies.md)); import-graph lint enforcing the layer rules ([Architecture §3](Architecture.md)); license-header check.

**`nightly.yml`.**
- Extended fuzzing (time-boxed hours, corpus auto-minimization, failures filed automatically with reproducers).
- Device farm lane (self-hosted runner with physical devices): Tier 3 suites — Secure Enclave, App Attest development-environment attestation, biometric UI lanes.
- Full TSan + address-sanitizer passes.
- Benchmarks on the fixed reference device; regression >10% auto-files an issue.
- Build against Xcode/Swift **beta** toolchains when Apple seeds them (failure files an issue, doesn't block PRs) — this is how "same-week OS support" ([MaintenanceStrategy](MaintenanceStrategy.md)) stays cheap.

**`release.yml` — tag-triggered.**
- Re-runs the full PR matrix + nightly suites from the tag.
- Format-compatibility gates (golden vaults/tokens from all prior releases).
- Builds and publishes versioned DocC to GitHub Pages.
- Drafts GitHub Release notes from `CHANGELOG.md`, benchmark summary attached.
- Verifies the tag is signed by a maintainer key ([ReleaseStrategy](ReleaseStrategy.md)).

## 2. Security of the Pipeline Itself

A security framework's CI is an attack target; we treat it as production:

- **Least-privilege tokens:** default `GITHUB_TOKEN` permissions `contents: read`; workflows escalate per-job only. No long-lived PATs.
- **Action pinning:** every third-party action pinned to a full commit SHA (never a tag); first-party (`actions/*`) preferred; the allowed-actions list is org-restricted.
- **No secrets in PR-triggered workflows.** Fork PRs run with zero secrets; device-farm and release jobs (which hold signing/device credentials) trigger only from `main`/tags with environment protection rules and required reviewers.
- **Runner hygiene:** the self-hosted device runner is network-segmented, auto-reimaged on schedule, and never executes fork code.
- Dependency-graph guard: CI fails if `Package.resolved` exists with any entry at all — the mechanical enforcement of zero-dependencies.

## 3. Branch Protection & Merge Policy

- `main`: PRs only; required checks = the full `pr.yml` matrix; linear history (squash merge); signed commits required for maintainers.
- Two-approval requirement auto-applied via CODEOWNERS when a diff touches security-sensitive paths (crypto, trust evaluation, token custody, CI itself) — the mechanical form of the [GOVERNANCE](../GOVERNANCE.md) rule.
- `release/x.y` branches: cherry-pick only, same protections.

## 4. What CI Never Does

- Never publishes on green alone — a human cuts releases ([ReleaseStrategy](ReleaseStrategy.md)).
- Never runs against live third-party services (IdPs, Apple's production App Attest) — hermetic harnesses and the development environment only.
- Never auto-fixes: formatters and linters *fail* PRs; rewriting contributor code silently hides the standard instead of teaching it.
