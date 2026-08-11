# Contributing to BlurSecurity

Thank you for helping build the security layer Apple apps deserve. This guide covers the practical path from idea to merged PR. The project's standards live in the [MANIFESTO](MANIFESTO.md); the process authority lives in [GOVERNANCE](GOVERNANCE.md).

## Before You Start

- **Vulnerabilities are never GitHub issues.** Follow [SECURITY.md](SECURITY.md) — private reporting only.
- **New public API starts as a discussion, not a PR.** Post the proposed *call sites* (how it reads in use) in GitHub Discussions → API Design. Design review happens before implementation, in the order users experience the API.
- **Structural changes need an ADR** ([template](docs/adr/template.md)) proposed in the PR itself.
- Check the [module specs](docs/modules/) first — most "should this exist?" questions are already answered there, including the deliberate omissions.

## Development Setup

Latest stable Xcode; no other tools required (zero dependencies is a feature you inherit — see [ADR-0002](docs/adr/0002-zero-third-party-dependencies.md)).

```
git clone <repo> && cd BlurSecurity
swift build && swift test          # Tier 1–2; device-tagged suites skip automatically
swift format lint --recursive .    # matches CI
```

## Branching & Commits

- Trunk-based: branch from `main` (`feature/<topic>`, `fix/<issue>`), squash-merge back. Release branches (`release/x.y`) take cherry-picks only.
- Commit messages: imperative summary line ≤ 72 chars; body explains *why*. PRs that change observable behavior include a `CHANGELOG.md` entry in the correct category — CI-checked, see [ReleaseStrategy §5](docs/ReleaseStrategy.md).

## Code Style

`swift-format` (config in-repo) settles formatting so review can be about substance. Beyond formatting:

- [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/) plus this project's [API Design Philosophy](docs/APIDesignPhilosophy.md) — the review checklist at its end is applied to every public-API PR, literally.
- `internal` by default; `public` is a reviewed decision with DocC on the same PR.
- Swift 6 strict concurrency, zero warnings. `@unchecked Sendable` needs the justification comment format from [ADR-0003](docs/adr/0003-swift6-strict-concurrency.md).
- One type per file; feature folders; no `Utils`. Tests follow [TestingStrategy §6](docs/TestingStrategy.md) — clock injection, no sleeps, suites named as specifications.
- Comments state constraints code can't express — never narrate the code.

## The PR Checklist

Every PR: builds clean on the matrix, tests for every behavior change (including the failure paths), DocC for every public symbol touched, changelog entry, `swift-format` clean. Public API PRs additionally: the [API review checklist](docs/APIDesignPhilosophy.md) answered in the description, and negative-compilation fixtures for any "cannot be misused" claim.

**Security-sensitive paths** (crypto, trust evaluation, keychain descriptor mapping, token custody, attestation state, CI workflows — enforced via CODEOWNERS) additionally require: two maintainer approvals and a **threat note** in the PR description — three sentences: what an attacker could try here, why this change doesn't help them, what test proves it.

## Review Culture

Reviews are prompt (first response ≤ 3 business days), specific, and kind. Reviewers distinguish *blocking* (correctness, security, API design, missing tests/docs) from *preference* (labeled as such, author's call). We review the code, never the person. Disagreements escalate per [GOVERNANCE](GOVERNANCE.md) — technical arguments, recorded outcomes.

## What Makes a Contribution Land Quickly

Small and focused beats large and mixed. Tests that show you probed the edges. Doc comments written for the completion popover. And for anything user-facing: show the call site first — if it reads beautifully, the rest of the review goes fast.

## Licensing

By contributing you agree your work ships under the project license. All files carry the standard header (CI-checked).
