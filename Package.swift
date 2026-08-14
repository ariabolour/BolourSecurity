// swift-tools-version: 6.0
// Swift-tools 6.0 makes Swift 6 language mode + complete strict concurrency the default.
import PackageDescription

let package = Package(
    name: "BlurSecurity",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        // Umbrella: everything with a single import.
        .library(name: "BlurSecurity", targets: ["BlurSecurity"]),
        // À-la-carte products, one per module.
        .library(name: "BlurSecurityCore", targets: ["BlurSecurityCore"]),
        .library(name: "BlurCrypto", targets: ["BlurCrypto"]),
        .library(name: "BlurKeychain", targets: ["BlurKeychain"]),
        .library(name: "BlurBiometrics", targets: ["BlurBiometrics"]),
        .library(name: "BlurCertificates", targets: ["BlurCertificates"]),
        .library(name: "BlurSecureStorage", targets: ["BlurSecureStorage"]),
        .library(name: "BlurNetworkSecurity", targets: ["BlurNetworkSecurity"]),
        .library(name: "BlurJWT", targets: ["BlurJWT"]),
        .library(name: "BlurAppIntegrity", targets: ["BlurAppIntegrity"]),
        .library(name: "BlurOAuth", targets: ["BlurOAuth"]),
    ],
    targets: [
        // Layer 0 — Foundation
        .target(name: "BlurSecurityCore"),

        // Layer 1 — Primitives
        .target(name: "BlurCrypto", dependencies: ["BlurSecurityCore"]),
        .target(name: "BlurKeychain", dependencies: ["BlurSecurityCore"]),

        // Layer 2 — Capabilities
        .target(name: "BlurBiometrics", dependencies: ["BlurSecurityCore"]),
        .target(name: "BlurCertificates", dependencies: ["BlurCrypto"]),
        .target(name: "BlurSecureStorage", dependencies: ["BlurKeychain", "BlurCrypto"]),

        // Layer 3 — Protocols & Services
        .target(name: "BlurNetworkSecurity", dependencies: ["BlurSecurityCore", "BlurCertificates"]),
        .target(name: "BlurJWT", dependencies: ["BlurSecurityCore", "BlurCrypto"]),
        .target(name: "BlurAppIntegrity", dependencies: ["BlurSecurityCore", "BlurCrypto", "BlurKeychain"]),

        // Layer 4 — Identity
        .target(name: "BlurOAuth", dependencies: ["BlurJWT", "BlurSecureStorage", "BlurNetworkSecurity"]),

        // Umbrella — re-exports every module.
        .target(name: "BlurSecurity", dependencies: [
            "BlurSecurityCore", "BlurCrypto", "BlurKeychain", "BlurBiometrics",
            "BlurCertificates", "BlurSecureStorage", "BlurNetworkSecurity",
            "BlurJWT", "BlurAppIntegrity", "BlurOAuth",
        ]),

        // Tests — added one per module as modules are implemented.
        .testTarget(name: "BlurSecurityCoreTests", dependencies: ["BlurSecurityCore"]),
        .testTarget(name: "BlurKeychainTests", dependencies: ["BlurKeychain", "BlurSecurityCore"]),
        .testTarget(name: "BlurCryptoTests", dependencies: ["BlurCrypto", "BlurSecurityCore"]),
        .testTarget(
            name: "BlurCertificatesTests",
            dependencies: ["BlurCertificates", "BlurSecurityCore"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(
            name: "BlurNetworkSecurityTests",
            dependencies: ["BlurNetworkSecurity", "BlurCertificates", "BlurSecurityCore"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(name: "BlurBiometricsTests", dependencies: ["BlurBiometrics", "BlurSecurityCore"]),
        .testTarget(
            name: "BlurSecureStorageTests",
            dependencies: ["BlurSecureStorage", "BlurKeychain", "BlurCrypto", "BlurSecurityCore"]
        ),
        .testTarget(
            name: "BlurAppIntegrityTests",
            dependencies: ["BlurAppIntegrity", "BlurKeychain", "BlurSecurityCore"]
        ),
        .testTarget(name: "BlurJWTTests", dependencies: ["BlurJWT", "BlurCrypto", "BlurSecurityCore"]),
    ]
)
