import Foundation
import Security
@testable import BolourCertificates

/// Distinguishes the two ways a `SecTrust` evaluation can come back negative: the chain was
/// evaluated and rejected (what these tests measure), or the Security subsystem never managed to
/// evaluate it at all (what a host without a reachable `trustd` or a usable keychain produces).
///
/// The distinction matters because every fail-closed test in this target asserts that a *bad*
/// chain is rejected. On a host where trust evaluation is broken outright, those assertions all
/// pass — for entirely the wrong reason — while the three happy-path tests fail. The suite then
/// looks like a chain-validation bug, and the three tests that still "pass" are measuring
/// nothing at all.
///
/// So: the suite is gated on ``isAvailable``, and the fail-closed tests assert on the *status*,
/// not merely on `CertificateError.self`. A genuine chain-validation regression still fails
/// loudly; only an unusable Security subsystem skips.
enum SystemTrustProbe {

    /// `OSStatus` values meaning "the evaluation did not happen", as opposed to "the chain was
    /// evaluated and found wanting".
    ///
    /// `errSecInternal` has no symbol in the public SDK (`SecBase.h` jumps from `errSecDecode`,
    /// -26275, straight to -67585) and `security error -26276` reports it as unknown, so it is
    /// spelled numerically. It is what the Security framework returns when its own daemons are
    /// unreachable — the usual cause being a process with no Mach bootstrap access to `trustd`.
    static let infrastructureFailureStatuses: Set<OSStatus> = [
        -26276,                       // errSecInternal: Security's daemons are unreachable.
        errSecNotAvailable,           // -25291: no trust/keychain service in this context.
        errSecNoDefaultKeychain,      // -25307: no default keychain (headless, no login session).
        errSecInteractionNotAllowed,  // -25308: a locked keychain nothing can unlock unattended.
        errSecServiceNotAvailable,    // -67585: the required service is not available.
        errSecMissingEntitlement,     // -34018: the host process is unentitled.
    ]

    /// True when this host can perform a `SecTrust` evaluation at all.
    ///
    /// Deliberately probes the Security APIs directly rather than going through
    /// ``TrustEvaluator``: the question is whether the *platform* works, and a probe that ran our
    /// own code would skip the suite on a `TrustEvaluator` regression instead of failing on it.
    static let isAvailable: Bool = {
        guard let leafDER = fixture("leaf-valid"), let rootDER = fixture("root"),
              let leaf = SecCertificateCreateWithData(nil, leafDER as CFData),
              let anchor = SecCertificateCreateWithData(nil, rootDER as CFData)
        else { return false }

        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, "valid.boloursecurity.test" as CFString)
        guard SecTrustCreateWithCertificates([leaf, anchor] as CFArray, policy, &trust) == errSecSuccess,
              let trust
        else { return false }
        SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)

        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) { return true }
        // A negative result on this known-good chain is itself a real failure worth reporting —
        // unless the subsystem is telling us it never did the work.
        guard let error else { return false }
        return !infrastructureFailureStatuses.contains(OSStatus(truncatingIfNeeded: CFErrorGetCode(error)))
    }()

    /// Whether `error` reports that trust evaluation could not be performed, rather than that a
    /// chain was rejected on its merits.
    static func isInfrastructureFailure(_ error: CertificateError) -> Bool {
        guard case .systemTrustFailed(let status, _) = error else { return false }
        return infrastructureFailureStatuses.contains(status)
    }

    private static func fixture(_ name: String) -> Data? {
        Bundle.module.url(forResource: name, withExtension: "der", subdirectory: "Fixtures")
            .flatMap { try? Data(contentsOf: $0) }
    }
}
