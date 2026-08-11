# The BlurSecurity Manifesto

We build the security layer every Apple app deserves and almost none has.

We believe security failures in apps are rarely failures of intent. They are failures of API design — of frameworks that made the insecure path shorter than the secure one, that returned `OSStatus` instead of guidance, that let a `Data` be a key, a password, a nonce, and a cat photo all at once.

So we hold these positions, and we design every line of public API against them.

## The Ten Laws of BlurSecurity

### 1. The default is the most secure option.
Every parameter with a default value defaults to the strongest reasonable setting. Keychain items are device-only and unlocked-only until a developer says otherwise. Ciphers are authenticated. Pinning fails closed. If a developer configures nothing, they get our best.

### 2. Insecurity is loud.
Weakening a guarantee must be visible at the call site, in code review, and in a `grep`. Anything that lowers protection carries an unmissable name — `unsafe`, `unvalidated`, `allowingDowngrade` — and never hides behind a boolean.

### 3. Types are the first line of defense.
A `SigningKey` cannot encrypt. A `Nonce` cannot be reused, because the API never accepts one twice. An unverified JWT is a different type from a verified one, and only the verified type exposes claims. If misuse can be made a compile-time error, it must be.

### 4. Abstract ceremony, never semantics.
We hide `CFDictionary`, `OSStatus`, `SecAccessControlCreateWithFlags`. We never hide *what protection the data actually has*. Every API names its guarantees; no method is more convenient than it is honest.

### 5. Errors teach.
Every error explains what failed, why it likely failed, and what to do next — without ever including secret material. An error message is a tiny piece of documentation delivered at the exact moment of need.

### 6. No dependencies, no exceptions.
BlurSecurity depends on Apple's SDKs and the Swift standard library. Nothing else, ever. Our supply chain is Apple's supply chain.

### 7. We do not invent cryptography.
Every primitive is Apple's: CryptoKit, Security.framework, LocalAuthentication, the Secure Enclave. BlurSecurity's contribution is *composition and API design*, not novel crypto. When Apple provides no primitive, we say so rather than improvise one.

### 8. Documentation is part of the API.
An undocumented public symbol is a build failure. Every module ships DocC with tutorials, security considerations, and the mistakes it prevents. If we can't explain an API simply, the API is wrong.

### 9. Every security decision leaves a record.
Architecture Decision Records for design. Two-maintainer review with threat notes for security-sensitive changes. Public advisories for vulnerabilities. Future contributors inherit our reasoning, not just our code.

### 10. Earn trust slowly; keep it obsessively.
We ship when it's right, not when it's due. We never break API in a minor version. We respond to every disclosed vulnerability with urgency and honesty. A security framework has exactly one asset: credibility.

## Engineering Principles

- **Swift 6, strict concurrency, no warnings.** Data races are security bugs. The codebase compiles clean under complete concurrency checking, always.
- **Value semantics first.** Configuration, policies, keys, and results are value types. Reference types and actors appear only where identity or serialization genuinely exists (sessions, token refresh).
- **`async/await` only.** No callback-based public APIs. The platform floor is chosen so we never need them.
- **Small public surface, deep behavior.** Every public symbol is a liability we maintain forever. We ship the minimal API that composes into everything, not the maximal API that anticipates everything.
- **Tests are specifications.** Swift Testing suites document behavior, including — especially — the failure paths. A security control without a test proving it fails closed does not exist.
- **Benchmarks prevent regressions from becoming habits.** Crypto and keychain operations sit on hot paths (app launch, request signing); we measure them per release.
- **The reviewer is the user.** APIs are judged by how call sites read in someone else's code review, five years from now, at 2 a.m., during an incident.

## The Test We Apply to Everything

Before any public API ships, it must survive four questions:

1. **Can it be held wrong?** If a plausible call site does something insecure, redesign.
2. **Does the obvious code do the right thing?** The first thing autocomplete suggests should be what a security engineer would have recommended.
3. **Would this make an Apple framework engineer proud?** Not "does it work" — is it *precise, minimal, and inevitable-feeling*?
4. **Can we explain it in one sentence?** If the doc comment's summary line needs a second sentence to avoid being misleading, the design is not done.

If the answer to any of these is no, we keep refining. We never optimize for speed of delivery. We always optimize for elegance, maintainability, correctness, security, and the experience of the developer who trusts us with their users' safety.
