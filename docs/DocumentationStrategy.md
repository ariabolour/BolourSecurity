# Documentation Strategy

Documentation is part of the API (Manifesto, Law 8). This document defines what we write, where it lives, and the gates that keep "100% documented" true forever.

## 1. Structure

**Per-module DocC catalogs** (`Sources/<Module>/<Module>.docc/`), each containing:

- **Landing page** — the module's mission in one paragraph, a three-line "first win" code sample, and a curated topic tree (never the default alphabetical dump).
- **Symbol documentation** — every public type, method, property, enum case, and protocol. Summary line ≤ 1 sentence; parameters/returns/throws documented; every `throws(E)` lists the cases a caller should realistically handle.
- **Security Considerations article** — required per module: the threat model addressed, the guarantees made, the honest limits (what this module does *not* protect against), and the mistakes it prevents. This article is reviewed by a second maintainer like code.
- **Common Mistakes article** — the anti-patterns from the module spec, shown as ❌/✅ compilable pairs.

**Umbrella catalog** (`Sources/BlurSecurity/BlurSecurity.docc/`):

- "Meet BlurSecurity" landing page and module directory.
- **Tutorials** (DocC interactive tutorials, Xcode-style): *Store Your First Secret* (BlurKeychain, 5 minutes), *Build a Biometric Vault* (SecureNotes walkthrough), *Ship Pinned Networking*, *Sign In with OAuth + PKCE*, *Prove Your App Is Real* (App Attest end-to-end including the server side).
- **Cross-cutting articles:** *Choosing a Storage Home* (Keychain vs TokenStore vs Vault decision tree), *Should You Pin?*, *The Threat Models BlurSecurity Addresses*, *Adopting BlurSecurity in a Regulated Industry* (what to show your auditor), *Migrating from Raw Security.framework*, *Migrating from KeychainAccess/Valet*.

**Repository docs** (`docs/`) — architecture, ADRs, strategy: for contributors and evaluators, not end users. The split is deliberate: DocC teaches *using* BlurSecurity; `docs/` explains *why it is the way it is*.

## 2. Voice and Standards

- Apple developer-documentation register: second person, present tense, active voice ("Store the token…" not "The token can be stored…").
- Every code sample **compiles**; samples are extracted and built in CI (a `DocSnippets` test target). A documentation example that rots is a lie with syntax highlighting.
- Security claims use calibrated language: *prevents* (type-system guarantee), *protects against* (OS-enforced), *raises the cost of* (mitigations like App Attest). The words are chosen per claim and reviewed — overclaiming is a doc bug of the highest severity.
- Error documentation teaches recovery, mirroring [ADR-0004](adr/0004-typed-throws-error-architecture.md).

## 3. Gates (what makes "100%" true)

- CI fails on any undocumented public symbol (DocC coverage audit + `--warnings-as-errors` on the documentation build).
- CI fails on broken symbol links (DocC link diagnostics).
- Snippet extraction target compiles on every PR.
- A public API PR without corresponding `.docc` changes fails review checklist item 7 ([APIDesignPhilosophy](APIDesignPhilosophy.md)).
- Each release's docs are published (docc static hosting via GitHub Pages) versioned alongside `main`'s.

## 4. Migration Guides

Every minor release with deprecations ships a migration article the same day, with mechanical before/after pairs. Major releases ship a dedicated migration guide **before** the release (during the RC window) so large apps can plan. Deprecation messages in code point at the exact replacement (`@available(*, deprecated, renamed:)` wherever mechanical).

## 5. Ownership

The module's maintainer owns its catalog; the Security Considerations articles are additionally owned by the security-review rotation ([GOVERNANCE.md](../GOVERNANCE.md)). Documentation debt is tracked as issues with the `documentation` label and blocks release the same way test failures do.
