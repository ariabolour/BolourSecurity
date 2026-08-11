# Governance

How decisions get made, who makes them, and the rules that keep a security project trustworthy as it grows. Designed for the project we intend to be (multi-maintainer, multi-organization) while stating honestly where we are (founding stage).

## Roles

**Contributor** — anyone with a merged PR or a substantive review/design contribution. No application; the work is the credential.

**Committer** — sustained, high-quality contributors granted triage + review rights, typically with informal ownership of a module's area. Nominated by a maintainer, confirmed by maintainer consensus. Committers' approvals count toward the standard review requirement (not the security-sensitive two-maintainer requirement).

**Maintainer** — merge rights, release rights (published signing keys — see [ReleaseStrategy](docs/ReleaseStrategy.md)), and accountability for the project's promises. New maintainers: nominated from committers, unanimous consent of existing maintainers, announced publicly. Maintainer accounts require hardware-key 2FA.

**Security-review rotation** — the maintainers currently sharing second-review duty for security-sensitive paths and ownership of Security Considerations documentation ([DocumentationStrategy](docs/DocumentationStrategy.md)). At founding scale this is all maintainers; it becomes a real rotation as the team grows.

## Decision Making

1. **Default: lazy consensus.** Proposals (issues, discussions, PRs) proceed when no maintainer objects within 5 business days. Silence is consent for routine matters.
2. **Structural decisions require an ADR** ([template](docs/adr/template.md)) and explicit (not lazy) approval — two maintainers, or all of them while the team is smaller than three.
3. **Security-sensitive changes** (the CODEOWNERS-enforced paths listed in [CONTRIBUTING](CONTRIBUTING.md)): two maintainer approvals + threat note, no exceptions, including for maintainers' own PRs.
4. **Disagreement:** technical arguments in the open, decided by maintainer consensus; if consensus fails, the module owner decides for module-scoped questions and a maintainer vote (simple majority) for ecosystem-scoped ones. Outcomes and reasoning are recorded (ADR or decision comment). We do not have a BDFL clause; we have a paper trail.

**What is never decidable by vote:** shipping a known vulnerability, weakening a shipped security default without the deprecation process, violating [ADR-0002](docs/adr/0002-zero-third-party-dependencies.md) (zero dependencies), or bypassing the two-review rule. These require amending this document first — visibly.

## The Sponsor Firewall

Funding ([MaintenanceStrategy §4](docs/MaintenanceStrategy.md)) buys maintenance time, never influence: sponsors get no review priority, no roadmap authority, no early vulnerability information beyond any public embargo program, and no logo-for-leniency. All funding sources are disclosed in the repository.

## Releases & Emergencies

Normal releases follow [ReleaseStrategy](docs/ReleaseStrategy.md). During an active security incident, the security-review rotation may operate a compressed process (private branch, embargoed fix, expedited review) — but the two-approval rule holds even then, and a public post-mortem follows every incident ([SECURITY.md](SECURITY.md)).

## Continuity

- Maintainers inactive for 6 months move to emeritus (honored, listed, no access) — reversible on return.
- Every maintainer keeps succession current: at least one committer per owned area who could assume ownership, named in the maintainers file.
- If the project ever winds down, the commitment is an orderly end: announcement, 18-month security-fix horizon honored, archive with clear "unmaintained" marking — never a silent Locksmith-style fade ([RiskAnalysis R8](docs/RiskAnalysis.md)).

## Amendments

Changes to this document: PR + all-maintainer approval + 2-week public comment period (community input explicitly invited).
