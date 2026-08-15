# Long-Term Maintenance Strategy

Security infrastructure is judged in year five, not week one. This document defines how BolourSecurity stays correct, current, and maintained on a decade horizon — the plan for being the opposite of the unmaintained wrapper our [CompetitiveAnalysis](CompetitiveAnalysis.md) warns about.

## 1. The Annual OS Cycle (the heartbeat)

Apple's June-to-September cadence is our largest recurring workload, so it runs as a standing process, not a scramble:

- **June (WWDC week):** triage every new/changed security-relevant API (Security, CryptoKit, LocalAuthentication, DeviceCheck, AuthenticationServices, Network) into: *adopt* (new capability → roadmap item + ADR if structural), *absorb* (behavior change beneath us → compatibility work), *ignore* (documented why). The triage doc is published in Discussions — adopters planning their own summers read it.
- **June–August:** beta-toolchain nightly lane ([CICDStrategy](CICDStrategy.md)) runs continuously; compatibility fixes land behind availability checks.
- **September (OS GM):** compatibility release within **one week** of GM — the "same-week support" promise from the [VISION](../VISION.md). New-API *adoption* ships later with proper design time; compatibility never waits for features.
- Platform floor review once per year, raising within the [ReleaseStrategy](ReleaseStrategy.md) policy only when the win is material (a floor raise is a minor, announced a release ahead).

## 2. Swift Toolchain Currency

Each Swift release gets a review: new language features against our idioms (adopt via ADR when they strengthen misuse-resistance), deprecation pressure, and a CI lane bump. We support building with the current Xcode and its predecessor; dropping the predecessor is announced one minor ahead.

## 3. Sustaining the Maintainer Base

The bus-factor risk ([RiskAnalysis R8](RiskAnalysis.md)) is managed by mechanism:

- **Knowledge lives in the repo:** ADRs for rationale, module specs for design, this strategy set for process. The standing rule — *if the project's continuity depends on something in someone's head, filing it is that person's highest-priority task.*
- **Contributor ladder** ([GOVERNANCE](../GOVERNANCE.md)): contributor → committer → maintainer, with deliberate cultivation — module ownership is delegated as committers prove depth (a realistic 2–3 year arc to multi-maintainer health).
- **Everything release-critical is CI-automated** — no laptop-resident release magic; a new maintainer can cut a release from the documented process alone.
- **Succession:** GOVERNANCE binds maintainers to name a successor path; a 6-month inactivity clause moves ownership without drama.

## 4. Funding & Sustainability Posture

Open source security work must not depend on burnout economics. Acceptable: GitHub Sponsors, foundation grants (e.g. sovereign tech / OSS security funds), corporate maintainer time — all disclosed publicly. Not acceptable, ever: pay-for-security-fixes, open-core forks of security features, sponsor influence over security decisions (GOVERNANCE encodes the firewall). The third-party audit (Year 3 vision) is the flagship funded milestone.

## 5. Dependency & Substrate Watch

Zero third-party dependencies removes dependency maintenance entirely ([ADR-0002](adr/0002-zero-third-party-dependencies.md)); what remains is *substrate watch*: quarterly review of Apple-SDK deprecations aimed at APIs we wrap, and the standing R5 posture ([RiskAnalysis](RiskAnalysis.md)) when Apple ships overlapping capability — adapt, don't compete.

## 6. Issue & Debt Hygiene

- Triage SLA: first response ≤ 3 business days (security reports: per [SECURITY.md](../SECURITY.md), 48 hours).
- Quarterly debt review: flaky-test quarantine emptied, fuzz corpora minimized, benchmark baselines re-validated, `@_spi(Experimental)` surface graduated or removed (experiments don't get to be permanent).
- Stale-issue policy that is honest rather than janitorial: auto-close only unreproducible reports; design discussions stay open as long as they're alive.

## 7. The Long-Game Definition of Done

Maintenance succeeds if, in any given year: every supported OS release was compatible within a week; every security report met its SLA; the maintainer set grew or held; no release broke semver; and the documentation still describes the code that ships. Those five facts, published annually in a state-of-the-project note, are the maintenance scorecard.
