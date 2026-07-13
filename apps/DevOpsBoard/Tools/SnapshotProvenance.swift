import CryptoKit
import Foundation

enum SnapshotSourceProvenance {
    static let boardSourceFiles = [
        "Package.swift",
        "Sources/DevOpsBoard/Models.swift",
        "Sources/DevOpsBoard/OpsStore.swift",
        "Sources/DevOpsBoard/RepositoryCatalog.swift",
        "Sources/DevOpsBoard/Views.swift",
        "Tools/CanonicalSnapshotGenerationTests.swift",
        "Tools/SnapshotMain.swift",
        "Tools/SnapshotProvenance.swift",
    ]

    static let menuSourceFiles = [
        "Package.swift",
        "Sources/DevOpsBoard/Models.swift",
        "Sources/DevOpsBoard/OpsStore.swift",
        "Sources/DevOpsBoard/RepositoryCatalog.swift",
        "Sources/DevOpsBoard/Views.swift",
        "Sources/DevOpsBoard/MenuBarViews.swift",
        "Tools/CanonicalSnapshotGenerationTests.swift",
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
            workingDirectory.appendingPathComponent("apps/DevOpsBoard", isDirectory: true),
        ]
        for candidate in candidates {
            let marker = candidate.appendingPathComponent(
                "Sources/DevOpsBoard/Views.swift",
                isDirectory: false
            )
            if FileManager.default.fileExists(atPath: marker.path) {
                return candidate.standardizedFileURL
            }
        }
        throw SnapshotSourceProvenanceError.projectRootNotFound
    }

    /// Canonical snapshots must exercise the same verified-worktree boundary
    /// as production. Keep the neutral repository fixture under ignored build
    /// output so it is real on disk without publishing runtime state.
    static func fixtureRepository(named name: String) throws -> URL {
        let root = try projectRoot()
            .appendingPathComponent(".build/qa/snapshot-fixtures", isDirectory: true)
            .appendingPathComponent(name, isDirectory: true)
            .standardizedFileURL
        let gitMarker = root.appendingPathComponent(".git", isDirectory: true)
        try FileManager.default.createDirectory(
            at: gitMarker,
            withIntermediateDirectories: true
        )
        guard FileManager.default.fileExists(atPath: gitMarker.path) else {
            throw SnapshotSourceProvenanceError.fixtureRepositoryUnavailable(root.path)
        }
        return root
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
    case fixtureRepositoryUnavailable(String)

    var errorDescription: String? {
        switch self {
        case .projectRootNotFound:
            "Could not locate the DevOpsBoard Sources and Tools directories for snapshot provenance."
        case let .fixtureRepositoryUnavailable(path):
            "Could not prepare the canonical snapshot repository fixture at \(path)."
        }
    }
}
