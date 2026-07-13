import Foundation
import XCTest

final class CanonicalSnapshotGenerationTests: XCTestCase {
    @MainActor
    func testRegenerateCanonicalArtifactsWhenExplicitlyEnabled() throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["DEVOPS_BOARD_REGENERATE_CANONICAL_SNAPSHOTS"] == "1" else {
            throw XCTSkip("Canonical snapshot generation requires an explicit regeneration request.")
        }

        let projectRoot = try SnapshotSourceProvenance.projectRoot()
        let outputDirectory = try approvedOutputDirectory(
            projectRoot: projectRoot,
            requestedPath: environment["DEVOPS_BOARD_SNAPSHOT_OUTPUT_DIR"]
        )

        try SnapshotMain.render(arguments: [
            outputDirectory.appendingPathComponent("dev-servers.png").path,
            "servers",
            "1440",
            "1024",
        ])
        try SnapshotMain.render(arguments: [
            outputDirectory.appendingPathComponent("docker-board.png").path,
            "docker",
            "1440",
            "1024",
        ])
        try SnapshotMain.render(arguments: [
            outputDirectory.appendingPathComponent("databases.png").path,
            "databases",
            "1440",
            "1024",
        ])
        try MenuBarSnapshotMain.render(arguments: [
            outputDirectory.appendingPathComponent("menu-action-error.png").path,
            "error",
        ])
    }
}

private func approvedOutputDirectory(projectRoot: URL, requestedPath: String?) throws -> URL {
    let canonicalDirectory = projectRoot
        .appendingPathComponent("Artifacts/Canonical", isDirectory: true)
        .standardizedFileURL
    guard let requestedPath, !requestedPath.isEmpty else {
        return canonicalDirectory
    }

    let requestedDirectory = URL(fileURLWithPath: requestedPath, isDirectory: true)
        .standardizedFileURL
    let qaDirectory = projectRoot
        .appendingPathComponent(".build/qa", isDirectory: true)
        .standardizedFileURL
    let qaPrefix = qaDirectory.path.hasSuffix("/") ? qaDirectory.path : qaDirectory.path + "/"
    guard requestedDirectory == canonicalDirectory || requestedDirectory.path.hasPrefix(qaPrefix) else {
        throw CanonicalSnapshotGenerationError.unapprovedOutputDirectory(requestedDirectory.path)
    }
    return requestedDirectory
}

private enum CanonicalSnapshotGenerationError: LocalizedError {
    case unapprovedOutputDirectory(String)

    var errorDescription: String? {
        switch self {
        case let .unapprovedOutputDirectory(path):
            "Snapshot output must be Artifacts/Canonical or a project-local .build/qa directory: \(path)"
        }
    }
}
