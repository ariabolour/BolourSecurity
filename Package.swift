// swift-tools-version: 6.0
// Swift-tools 6.0 makes Swift 6 language mode + complete strict concurrency the default.
import PackageDescription

let package = Package(
    name: "BolourSecurity",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        // Umbrella: everything with a single import.
        .library(name: "BolourSecurity", targets: ["BolourSecurity"]),
        // À-la-carte products, one per module.
        .library(name: "BolourSecurityCore", targets: ["BolourSecurityCore"]),
        .library(name: "BolourCrypto", targets: ["BolourCrypto"]),
        .library(name: "BolourKeychain", targets: ["BolourKeychain"]),
        .library(name: "BolourBiometrics", targets: ["BolourBiometrics"]),
        .library(name: "BolourCertificates", targets: ["BolourCertificates"]),
        .library(name: "BolourSecureStorage", targets: ["BolourSecureStorage"]),
        .library(name: "BolourNetworkSecurity", targets: ["BolourNetworkSecurity"]),
        .library(name: "BolourJWT", targets: ["BolourJWT"]),
        .library(name: "BolourAppIntegrity", targets: ["BolourAppIntegrity"]),
        .library(name: "BolourOAuth", targets: ["BolourOAuth"]),
    ],
    targets: [
        // Layer 0 — Foundation
        .target(name: "BolourSecurityCore"),

        // Layer 1 — Primitives
        .target(name: "BolourCrypto", dependencies: ["BolourSecurityCore"]),
        .target(name: "BolourKeychain", dependencies: ["BolourSecurityCore"]),

        // Layer 2 — Capabilities
        .target(name: "BolourBiometrics", dependencies: ["BolourSecurityCore"]),
        .target(name: "BolourCertificates", dependencies: ["BolourCrypto"]),
        .target(name: "BolourSecureStorage", dependencies: ["BolourKeychain", "BolourCrypto"]),

        // Layer 3 — Protocols & Services
        .target(name: "BolourNetworkSecurity", dependencies: ["BolourSecurityCore", "BolourCertificates"]),
        .target(name: "BolourJWT", dependencies: ["BolourSecurityCore", "BolourCrypto"]),
        .target(name: "BolourAppIntegrity", dependencies: ["BolourSecurityCore", "BolourCrypto", "BolourKeychain"]),

        // Layer 4 — Identity
        .target(name: "BolourOAuth", dependencies: ["BolourSecurityCore", "BolourJWT", "BolourSecureStorage", "BolourNetworkSecurity"]),

        // Umbrella — re-exports every module.
        .target(name: "BolourSecurity", dependencies: [
            "BolourSecurityCore", "BolourCrypto", "BolourKeychain", "BolourBiometrics",
            "BolourCertificates", "BolourSecureStorage", "BolourNetworkSecurity",
            "BolourJWT", "BolourAppIntegrity", "BolourOAuth",
        ]),

        // Tests — added one per module as modules are implemented.
        .testTarget(name: "BolourSecurityCoreTests", dependencies: ["BolourSecurityCore"]),
        .testTarget(name: "BolourKeychainTests", dependencies: ["BolourKeychain", "BolourSecurityCore"]),
        .testTarget(name: "BolourCryptoTests", dependencies: ["BolourCrypto", "BolourSecurityCore"]),
        .testTarget(
            name: "BolourCertificatesTests",
            dependencies: ["BolourCertificates", "BolourSecurityCore"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(
            name: "BolourNetworkSecurityTests",
            dependencies: ["BolourNetworkSecurity", "BolourCertificates", "BolourSecurityCore"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(name: "BolourBiometricsTests", dependencies: ["BolourBiometrics", "BolourSecurityCore"]),
        .testTarget(
            name: "BolourSecureStorageTests",
            dependencies: ["BolourSecureStorage", "BolourKeychain", "BolourCrypto", "BolourSecurityCore"]
        ),
        .testTarget(
            name: "BolourAppIntegrityTests",
            dependencies: ["BolourAppIntegrity", "BolourKeychain", "BolourSecurityCore"]
        ),
        .testTarget(name: "BolourJWTTests", dependencies: ["BolourJWT", "BolourCrypto", "BolourSecurityCore"]),
        .testTarget(
            name: "BolourOAuthTests",
            dependencies: ["BolourOAuth", "BolourJWT", "BolourCrypto", "BolourSecurityCore"]
        ),
    ]
)
