// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "CodexOpsConsole",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "CodexOpsConsole", targets: ["CodexOpsConsole"])
    ],
    targets: [
        .executableTarget(name: "CodexOpsConsole"),
        .testTarget(name: "CodexOpsConsoleTests", dependencies: ["CodexOpsConsole"])
    ]
)
