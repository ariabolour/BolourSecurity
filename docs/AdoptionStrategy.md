# Adoption Strategy

BolourSecurity wins adoption the way infrastructure does: by being obviously correct, easy to start, and safe to bet on. No growth hacks — credibility compounding.

## 1. Positioning

**One-line pitch:** *The security foundation for modern Apple apps — Keychain, crypto, biometrics, pinning, JWT, and OAuth with Apple-quality Swift APIs that are safe by default.*

Against the field ([CompetitiveAnalysis](CompetitiveAnalysis.md)): existing options are single-purpose wrappers (KeychainAccess, Valet), unmaintained (Locksmith), non-native ports (CryptoSwift — which also means non-hardware-backed crypto), or Java-lineage (AppAuth). Nothing offers a coherent, Swift-6-native, zero-dependency *platform*. That's the category we create and name: not "a keychain library," but **the security layer**.

**Audience order:** (1) senior iOS engineers at regulated-industry companies — highest pain, strongest need for our exact guarantees, best credibility flywheel; (2) indie/small teams — broadest reach, loudest advocacy; (3) security engineers who *recommend* dependencies — they don't adopt, they multiply.

## 2. Launch Sequence

- **0.1 (quiet):** public repo with this documentation set complete before wide announcement — evaluators who arrive early find ADRs and specs, not promises. Early adopters recruited directly for design feedback.
- **0.5 (soft launch):** Swift Forums (Related Projects) introduction focused on API design decisions — the forums reward design depth; blog series *Designing APIs That Can't Be Held Wrong* (the phantom-type JWT, the unconstructible single-pin policy — each post is a case study that markets by teaching).
- **1.0 (launch):** the stability promise is the story. Benchmarks published, docs site live, migration guides from raw SDK + KeychainAccess + Valet ready on day one. Conference-talk submissions (the API-design story is genuinely novel talk material), podcast circuit, newsletter outreach (iOS Dev Weekly et al. cover substance).
- **Post-1.0:** case studies from regulated-industry adopters (the *Adopting in a Regulated Industry* article makes this concrete); third-party audit ([Five-Year Vision](../VISION.md)) becomes the trust headline of the 2.x era.

## 3. Migration as an Adoption Weapon

Most targets already have security code. Migration guides are therefore first-class product surface:

- *From raw Security.framework* — the mechanical `SecItemAdd` → `Keychain` mapping table.
- *From KeychainAccess / Valet* — API correspondence plus the `migrate(from: legacyQuery)` helper ([BolourKeychain roadmap](modules/BolourKeychain.md)) that reads existing items in place — adopting must never mean logging users out.
- *Coexistence guarantee:* BolourSecurity touches only its own items/state; incremental, module-by-module adoption is the documented default path. "Try `BolourKeychain` in one feature" is the wedge; the ecosystem's coherence does the rest.

## 4. Trust Signals (the checklist evaluators bring)

Working in our favor by design: zero dependencies, 100% documented, ADRs public, security policy with response targets, signed releases, benchmark transparency, honest-limits documentation (the rarest signal — we state what we *don't* protect against). Each is worth more than any marketing copy; the AdoptionStrategy is largely "make the true things visible."

## 5. Community Growth

- `good-first-issue` gardening with genuinely scoped issues; contribution ladder documented in [GOVERNANCE](../GOVERNANCE.md).
- API design discussions in public (Discussions) before implementation — contributors who shape an API become its advocates.
- Fast, kind, honest review ([CONTRIBUTING](../CONTRIBUTING.md) sets the tone). Reputation among contributors is adoption infrastructure.

## 6. Measures (health, not vanity)

Production adoptions we know of (self-reported registry in Discussions), migration-guide traffic, time-to-first-response on issues, external-contributor share of merged PRs, and — the north star — *reported security issues in adopting apps traced to BolourSecurity misuse*, which should trend toward structurally impossible.
