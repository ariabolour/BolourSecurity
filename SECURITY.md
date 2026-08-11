# Security Policy

BlurSecurity exists to protect apps and their users. Reports of vulnerabilities in BlurSecurity itself are the most important issues we can receive, and this policy is our commitment to handling them seriously, fast, and honestly.

## Reporting a Vulnerability

**Never open a public GitHub issue for a suspected vulnerability.**

Report privately via **GitHub Security Advisories** ("Report a vulnerability" on the repository's Security tab) — the preferred channel. If that is unavailable to you, email **blor1379@gmail.com** with `[SECURITY]` in the subject.

Please include: affected module(s) and version(s), a description of the issue and its impact as you understand it, reproduction steps or proof-of-concept if you have one, and how you'd like to be credited. Partial reports are welcome — do not sit on a suspicion because the write-up isn't polished.

## Our Commitments

| Stage | Target |
|---|---|
| Acknowledgement | **48 hours** |
| Triage & severity assessment shared with reporter | 5 business days |
| Fix for confirmed Critical/High issues | 30 days (target, not ceiling — usually far less) |
| Fix for Moderate/Low issues | Next scheduled release, ≤ 90 days |

- We keep reporters informed throughout and coordinate disclosure timing with them; our default is publication when the fix ships.
- Security fixes ship as **patch releases on every supported version** ([ReleaseStrategy](docs/ReleaseStrategy.md) defines the support window: latest minor of the current major, plus the final minor of the previous major for 18 months).
- Every advisory is published via GitHub Security Advisories with CVE where applicable, an honest severity assessment, affected/fixed versions, and workarounds if any exist.
- Every incident gets a public post-mortem; structural lessons become ADRs ([RiskAnalysis](docs/RiskAnalysis.md)).
- Credit is given as the reporter prefers, including anonymity. We do not currently run a paid bounty; we say so plainly rather than imply otherwise.

## Scope

**In scope:** any way BlurSecurity's code, defaults, or documentation causes an adopting app to be less secure than promised — including misuse-resistance failures (an API that can be held wrong in a way our design claims impossible) and documentation that materially overclaims ([RiskAnalysis R4](docs/RiskAnalysis.md)). Those are security bugs here, not paper cuts.

**Out of scope:** vulnerabilities in Apple's frameworks (report to Apple; we'll mitigate where we can and document where we can't), issues requiring a compromised OS beyond our documented threat models, and vulnerabilities in apps' own code using our APIs as documented.

## Safe Harbor

Good-faith research against your own installations of BlurSecurity is welcome. We will never pursue or support action against researchers acting in good faith within this policy.

## For Adopters

- Watch: GitHub Releases + Security Advisories for this repository (advisories are machine-readable for dependency scanners).
- The `Security` section of the [CHANGELOG](CHANGELOG.md) is never omitted — releases with no security content say so explicitly.
- Each module's DocC includes a *Security Considerations* article stating its threat model and honest limits; adopting teams in regulated industries should read those articles as part of their assessment — that's what they're for.
