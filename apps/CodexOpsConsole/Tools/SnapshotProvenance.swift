import CryptoKit
import Foundation

enum SnapshotSourceProvenance {
    static let boardSourceFiles = [
        "Sources/CodexOpsConsole/Models.swift",
        "Sources/CodexOpsConsole/OpsStore.swift",
        "Sources/CodexOpsConsole/Views.swift",
        "Tools/SnapshotMain.swift",
        "Tools/SnapshotProvenance.swift",
    ]

    static let menuSourceFiles = [
        "Sources/CodexOpsConsole/Models.swift",
        "Sources/CodexOpsConsole/OpsStore.swift",
        "Sources/CodexOpsConsole/Views.swift",
        "Sources/CodexOpsConsole/MenuBarViews.swift",
        "Tools/MenuBarSnapshotMain.swift",
        "Tools/SnapshotProvenance.swift",
    ]

    static func projectRoot() throws -> URL {
        let workingDirectory = URL(
            fileURLWithPath: FileManager.default.currentDirectoryPath,
            isDirectory: true
        ).standardizedFileURL
        let candidates = [
            workingDirectory,
            workingDirectory.appendingPathComponent("apps/CodexOpsConsole", isDirectory: true),
        ]
        for candidate in candidates {
            let marker = candidate.appendingPathComponent(
                "Sources/CodexOpsConsole/Views.swift",
                isDirectory: false
            )
            if FileManager.default.fileExists(atPath: marker.path) {
                return candidate.standardizedFileURL
            }
        }
        throw SnapshotSourceProvenanceError.projectRootNotFound
    }

    static func fingerprint(sourceRoot: URL, relativePaths: [String]) throws -> String {
        var hasher = SHA256()
        for relativePath in relativePaths.sorted() {
            let sourceURL = sourceRoot.appendingPathComponent(relativePath, isDirectory: false)
            let data = try Data(contentsOf: sourceURL)
            hasher.update(data: Data(relativePath.utf8))
            hasher.update(data: Data([0]))
            hasher.update(data: data)
            hasher.update(data: Data([0]))
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

enum SnapshotSourceProvenanceError: LocalizedError {
    case projectRootNotFound

    var errorDescription: String? {
        switch self {
        case .projectRootNotFound:
            "Could not locate the CodexOpsConsole Sources and Tools directories for snapshot provenance."
        }
    }
}
