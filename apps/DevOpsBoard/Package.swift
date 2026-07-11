// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "DevOpsBoard",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "DevOpsBoard", targets: ["DevOpsBoard"])
    ],
    targets: [
        .executableTarget(name: "DevOpsBoard"),
        .testTarget(name: "DevOpsBoardTests", dependencies: ["DevOpsBoard"])
    ]
)
