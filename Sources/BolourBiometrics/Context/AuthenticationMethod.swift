/// Which mechanism satisfied an `authenticate` call.
///
/// - Note: LocalAuthentication doesn't report *how* a policy was satisfied, only that it was —
///   `.faceID`/`.touchID`/`.opticID` are inferred from the device's enrolled biometry at success
///   time, which is correct except in the rare case a user tapped "Enter Passcode" on a device
///   that also has biometry enrolled (LocalAuthentication surfaces that choice as the distinct
///   `userFallback` *error*, never folded into a success, so this inference only misses the
///   passcode-typed-anyway path inside an already-successful biometric prompt, which the OS does
///   not distinguish either).
public enum AuthenticationMethod: Sendable, Hashable {
    case faceID
    case touchID
    case opticID
    case passcode
    case watch
}
