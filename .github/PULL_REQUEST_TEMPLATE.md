<!-- Thanks for contributing. Keep PRs small and focused; link the issue or discussion this implements. -->

## What & Why

<!-- One paragraph: the change and the reason. Link issues/discussions/ADRs. -->

## Checklist

- [ ] Tests cover the change, **including failure paths** (see [TestingStrategy](../docs/TestingStrategy.md))
- [ ] `CHANGELOG.md` entry in the correct category (or: no observable behavior change)
- [ ] DocC updated for every public symbol touched (or: no public API touched)
- [ ] `swift-format` clean; zero warnings under strict concurrency

## Public API changes

<!-- Delete this section if none. Otherwise: answer the API review checklist from
     docs/APIDesignPhilosophy.md here — defaults, misuse analysis, naming, error
     domain, and how the call site reads. Negative-compilation fixtures included
     for any "cannot be misused" claim. -->

## Threat note (required for security-sensitive paths)

<!-- Required when touching: crypto, trust evaluation, keychain descriptor mapping,
     token custody, attestation state, or CI workflows (CODEOWNERS will require two
     maintainer approvals). Three sentences:
     1. What could an attacker try here?
     2. Why doesn't this change help them?
     3. Which test proves it? -->
