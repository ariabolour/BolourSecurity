# Risk Analysis

Named risks, honest likelihoods, and the mitigations we run *before* they materialize. Reviewed every six months and after any incident; each risk names an owner (maintainer rotation until the team grows).

## Security Risks (highest stakes)

**R1 — A vulnerability ships in a release.** *Likelihood: eventual certainty at scale. Impact: severe.*
Mitigations: adversarial test tiers + fuzzing + attack corpora ([TestingStrategy](TestingStrategy.md)); two-maintainer review with threat notes on sensitive paths ([GOVERNANCE](../GOVERNANCE.md)); no invented crypto (Law 7) keeps the worst class off the table; narrow public surface. Response readiness: disclosure policy with targets ([SECURITY.md](../SECURITY.md)), patch-only security releases on all supported minors ([ReleaseStrategy](ReleaseStrategy.md)), pre-drafted advisory template. *The plan assumes it will happen and optimizes time-to-remediation and honesty of disclosure.*

**R2 — An API we shipped turns out to be holdable-wrong.** *Likelihood: moderate. Impact: high (our core promise).*
Mitigations: the four-question API test ([MANIFESTO](../MANIFESTO.md)), review checklist, `@_spi(Experimental)` soak time for novel surface. Response: security-motivated deprecation fast path ([ReleaseStrategy §4](ReleaseStrategy.md)) with runtime `SecurityEvent` warnings on the unsafe pattern.

**R3 — Supply-chain compromise of our pipeline.** *Likelihood: low. Impact: severe.*
Mitigations: zero dependencies removes the classic vector entirely ([ADR-0002](adr/0002-zero-third-party-dependencies.md)); CI hardening — SHA-pinned actions, least-privilege tokens, no secrets on fork PRs, segmented device runner ([CICDStrategy §2](CICDStrategy.md)); signed tags with published maintainer keys; maintainer accounts require hardware-key 2FA.

**R4 — Overclaiming.** A doc or API name promises more than the platform delivers (zeroization, jailbreak resistance). *Likelihood: moderate — it's the industry default failure. Impact: reputational, and real harm to users who believed us.*
Mitigations: calibrated-language rule ([DocumentationStrategy §2](DocumentationStrategy.md)); "honest limits" sections mandatory per module; security-claims review by second maintainer. This risk is why `SecureBytes` documents best-effort zeroing instead of promising guarantees Swift can't keep.

## Platform Risks

**R5 — Apple ships overlapping first-party APIs.** *Likelihood: moderate over 5 years. Impact: existential-sounding, actually survivable.*
Posture (pre-committed so we don't rationalize in the moment): **celebrate publicly, adopt the first-party API as our substrate where it's better, deprecate our overlap with migration guides.** The ecosystem coherence and the modules Apple won't ship (OAuth custody, JWT, pinning policy) remain. Wrapper-drift's opposite — being *first to build on* new Apple API — is the same muscle as R6's mitigation.

**R6 — Wrapper drift: OS releases change behavior beneath us.** *Likelihood: annual certainty. Impact: moderate, compounding if ignored.*
Mitigations: beta-toolchain nightly lane ([CICDStrategy](CICDStrategy.md)); June-readiness process ([MaintenanceStrategy](MaintenanceStrategy.md)); thin total mappings over OS APIs (drift surfaces as compile errors, not silent behavior change); Tier 3 device tests catch semantic drift the compiler can't.

**R7 — Swift language evolution obsoletes our idioms.** *Likelihood: certain, slow. Impact: low each step.*
Typed throws, strict concurrency put us at the modern edge at launch; the risk is standing still. Mitigation: language-feature review each Swift release; `@_spi(Experimental)` lets us trial idioms without commitment.

## Project Risks

**R8 — Bus factor: founding-maintainer concentration.** *Likelihood: high initially. Impact: fatal if unaddressed — Locksmith is the cautionary tale ([CompetitiveAnalysis](CompetitiveAnalysis.md)).*
Mitigations: this documentation set *is* the primary mitigation — architecture, rationale, and process live in the repo, not in heads; contributor ladder with deliberate committer cultivation ([GOVERNANCE](../GOVERNANCE.md)); everything release-critical runs in CI, not on laptops; explicit succession clause in GOVERNANCE.

**R9 — Scope creep.** Security touches everything; "just add jailbreak detection / analytics / UI" pressure is constant. *Likelihood: high. Impact: erosion of the one-responsibility architecture and of trust (jailbreak detection especially invites the checkbox-security dynamic).*
Mitigations: "What BlurSecurity Deliberately Does Not Do" ([Architecture §9](Architecture.md)) as the standing answer; new-module bar requires an ADR; the deleted-BlurUtilities precedent ([ADR-0005](adr/0005-consolidated-module-set.md)).

**R10 — Trust is slow; adoption stalls pre-1.0.** *Likelihood: moderate. Impact: motivational/sustainability.*
Mitigations: the wedge strategy (single-module adoption, migration helpers — [AdoptionStrategy](AdoptionStrategy.md)); regulated-industry focus where the pain is sharpest; patience as policy — the [VISION](../VISION.md) five-year arc budgets for slow compounding, and "never optimize for speed" applies to growth too.

**R11 — A well-resourced competitor executes the platform thesis first.** *Likelihood: low-moderate. Impact: moderate.*
Mitigations: design quality and published trust signals are slow-to-copy moats; our zero-dependency + honest-limits posture is structurally hard for a VC-backed entrant to match. If someone does it *better*, users win — and we say so; credibility survives losing a race, not denying one.

## Standing Review

Every incident (security or process) produces a public post-mortem and, where structural, an ADR. Risks retire only by mechanism, never by optimism.
