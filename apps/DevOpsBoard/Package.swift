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
        .testTarget(name: "DevOpsBoardTests", dependencies: ["DevOpsBoard"]),
        .testTarget(
            name: "DevOpsBoardSnapshotTests",
            dependencies: ["DevOpsBoard"],
            path: "Tools",
            exclude: [
                "SplitSizingTest.swift",
                "package_app.py",
                "self_test_package_app.py",
                "self_test_verify_launch_readiness.py",
                "verify_launch_readiness.py",
            ],
            sources: [
                "CanonicalSnapshotGenerationTests.swift",
                "MenuBarSnapshotMain.swift",
                "SnapshotMain.swift",
                "SnapshotProvenance.swift",
            ]
        )
    ]
)
