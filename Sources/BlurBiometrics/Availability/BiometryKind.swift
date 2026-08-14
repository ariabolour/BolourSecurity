import LocalAuthentication

/// Which biometric modality is present.
public enum BiometryKind: Sendable, Hashable {
    case faceID
    case touchID
    case opticID

    /// `nil` for `.none` (no biometric hardware) or any future type this package doesn't know about.
    init?(_ type: LABiometryType) {
        switch type {
        case .faceID: self = .faceID
        case .touchID: self = .touchID
        case .opticID: self = .opticID
        default: return nil
        }
    }
}
