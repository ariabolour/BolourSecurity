import Foundation

/// The reason string shown in the system authentication prompt.
///
/// Localizable by construction — the ordinary spelling (`AuthenticationReason("...")`) takes a
/// `String.LocalizationValue`, so a lazy, unlocalized literal is the *unusual* spelling
/// (`verbatim:`), not the default. Both spellings reject an empty resolved string: "because the
/// API demanded a string" prompts become impossible to ship, not merely discouraged.
public struct AuthenticationReason: Sendable, Hashable {
    let resolvedString: String

    /// Resolves `key` against `bundle` immediately, so a missing localization is caught at the
    /// call site rather than surfacing as a blank system prompt in production.
    public init(_ key: String.LocalizationValue, bundle: Bundle = .main) {
        self.init(verbatim: String(localized: key, bundle: bundle))
    }

    /// An escape hatch for dynamic text (e.g. text already localized upstream). Crashes on an
    /// empty string — the same contract as the localized initializer, just enforced directly
    /// since there's no localization table to catch it first.
    public init(verbatim: String) {
        precondition(AuthenticationReason.isValid(verbatim), "AuthenticationReason must not be empty")
        self.resolvedString = verbatim
    }

    static func isValid(_ string: String) -> Bool { !string.isEmpty }
}
