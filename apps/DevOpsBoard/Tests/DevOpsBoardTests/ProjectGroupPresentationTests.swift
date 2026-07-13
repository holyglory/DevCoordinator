import Foundation
import XCTest
@testable import DevOpsBoard

final class ProjectGroupPresentationTests: XCTestCase {
    private let left = CoordinatorOrigin(
        label: "Left Codex",
        home: "/fixtures/coordinators/left"
    )
    private let right = CoordinatorOrigin(
        label: "Right Codex",
        home: "/fixtures/coordinators/right"
    )

    func testUnassignedPresentationHidesProjectActionsAndPreservesEveryObservedSource() {
        let group = ProjectGroup(
            id: unassignedProjectGroupID,
            name: "Unassigned Resources",
            projectPath: nil,
            servers: [],
            containers: [],
            databases: [],
            usage: nil,
            kind: .unassigned,
            observedOrigins: [right, left, right],
            usesCatalogControlBinding: true
        )

        XCTAssertFalse(projectGroupShowsProjectActions(group))
        XCTAssertEqual(projectGroupObservedOrigins(group), [left, right])
        XCTAssertNil(projectGroupConflictSummary(group))
    }

    func testRepositoryConflictPresentationIsUnhealthyAndNamesActiveSources() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("project-group-presentation-\(UUID().uuidString)", isDirectory: true)
        let repositoryURL = root.appendingPathComponent("Nevod", isDirectory: true)
        try FileManager.default.createDirectory(
            at: repositoryURL.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try XCTUnwrap(RepositoryIdentity(projectPath: repositoryURL.path))
        let conflict = RepositoryServerConflict(
            service: RepositoryLogicalServerIdentity(repository: repository, serviceName: "web"),
            activeSourceIdentities: [
                ResourceIdentity(origin: right, kind: .server, nativeID: "web"),
                ResourceIdentity(origin: left, kind: .server, nativeID: "web"),
            ]
        )
        let group = ProjectGroup(
            id: "path:\(repository.canonicalRoot)",
            name: "Nevod",
            projectPath: repository.canonicalRoot,
            servers: [],
            containers: [],
            databases: [],
            usage: nil,
            kind: .repository,
            observedOrigins: [left, right],
            serverConflicts: [conflict],
            usesCatalogControlBinding: true
        )

        XCTAssertTrue(projectGroupShowsProjectActions(group))
        XCTAssertEqual(projectGroupStatus(group), "unhealthy")
        XCTAssertEqual(projectGroupConflictSummary(group), conflict.message)
        XCTAssertEqual(projectConflictOrigins(conflict), [left, right])
    }

    func testNormalRepositoryRemainsAProjectActionFalsePositiveControl() {
        let group = ProjectGroup(
            id: "path:/fixtures/projects/healthy",
            name: "healthy",
            projectPath: "/fixtures/projects/healthy",
            servers: [],
            containers: [],
            databases: [],
            usage: nil,
            kind: .repository,
            controlOrigin: left,
            observedOrigins: [left],
            usesCatalogControlBinding: true
        )

        XCTAssertTrue(projectGroupShowsProjectActions(group))
        XCTAssertEqual(projectGroupStatus(group), "stopped")
        XCTAssertNil(projectGroupConflictSummary(group))
    }

    func testResourceSourcePresentationKeepsPrimaryAndCandidateOriginsWithoutDuplicates() {
        XCTAssertEqual(
            resourceObservationOrigins(primary: right, candidates: [left, right, left]),
            [left, right]
        )
        XCTAssertEqual(resourceObservationOrigins(primary: left, candidates: []), [left])
        XCTAssertTrue(resourceObservationOrigins(primary: nil, candidates: []).isEmpty)
    }
}
