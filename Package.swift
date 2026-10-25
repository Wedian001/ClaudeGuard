// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ClaudeGuard",
    platforms: [
        .macOS("26.0")
    ],
    products: [
        .library(name: "ClaudeGuardCore", targets: ["ClaudeGuardCore"]),
        .executable(name: "ClaudeGuardApp", targets: ["ClaudeGuardApp"]),
        .executable(name: "claude-guard", targets: ["ClaudeGuardCLI"])
    ],
    targets: [
        .target(
            name: "ClaudeGuardCore",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("Network"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("CFNetwork"),
                .linkedFramework("UserNotifications"),
                .linkedFramework("ServiceManagement")
            ]
        ),
        .executableTarget(
            name: "ClaudeGuardApp",
            dependencies: ["ClaudeGuardCore"],
            linkerSettings: [
                .linkedFramework("SwiftUI"),
                .linkedFramework("AppKit")
            ]
        ),
        .executableTarget(
            name: "ClaudeGuardCLI",
            dependencies: ["ClaudeGuardCore"]
        ),
        .testTarget(
            name: "ClaudeGuardTests",
            dependencies: ["ClaudeGuardCore"]
        )
    ]
)
