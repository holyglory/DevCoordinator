import Foundation
import XCTest
@testable import DevOpsBoard

final class CoreTests: XCTestCase {
    private let codex = CoordinatorOrigin(label: "Codex", home: "/tmp/codex-home")
    private let parall = CoordinatorOrigin(label: "Parall", home: "/tmp/parall-home")

    func testCompositeIdentityKeepsCollidingResourcesDistinct() {
        let left = ResourceIdentity(origin: codex, kind: .server, nativeID: "web")
        let right = ResourceIdentity(origin: parall, kind: .server, nativeID: "web")
        XCTAssertNotEqual(left, right)
        XCTAssertNotEqual(left.rawValue, right.rawValue)
    }

    func testCoordinatorClientRoutesEveryActionThroughOwningHome() async throws {
        let executor = RecordingCommandExecutor(result: .init(stdout: "{}", stderr: "", exitStatus: 0))
        let service = PythonCoordinatorService(executor: executor, scriptPath: "/repo/coordinator.py")

        _ = try await service.execute(origin: parall, arguments: ["server", "status"])

        let captured = await executor.capturedRequests()
        let request = try XCTUnwrap(captured.first)
        XCTAssertEqual(request.environment["CODEX_AGENT_COORDINATOR_HOME"], parall.home)
        XCTAssertEqual(request.arguments, ["python3", "/repo/coordinator.py", "server", "status"])
    }

    func testPartialSourceHealthNeverReportsNominal() {
        let now = Date(timeIntervalSince1970: 100)
        let sources = [
            CoordinatorSourceState(origin: codex, phase: .loaded, checkedAt: now, resourceCount: 2),
            CoordinatorSourceState(origin: parall, phase: .failed, checkedAt: now, error: "permission denied")
        ]
        let summary = HealthSummary.reduce(sources: sources, resourceSignals: [], actions: [], now: now)
        XCTAssertEqual(summary.level, .degraded)
        XCTAssertFalse(summary.isComplete)
        XCTAssertEqual(summary.failedSourceCount, 1)
    }

    func testOnlyStaleSourceIsUsableOnlyWhenRetainedEvidenceExists() {
        let now = Date(timeIntervalSince1970: 100)
        let retained = HealthSummary.reduce(
            sources: [.init(origin: codex, phase: .stale, checkedAt: now, resourceCount: 2, error: "refresh failed")],
            resourceSignals: [],
            actions: [],
            now: now
        )
        XCTAssertEqual(retained.level, .degraded)
        XCTAssertFalse(retained.isComplete)

        let empty = HealthSummary.reduce(
            sources: [.init(origin: codex, phase: .stale, checkedAt: now, resourceCount: 0, error: "refresh failed")],
            resourceSignals: [],
            actions: [],
            now: now
        )
        XCTAssertEqual(empty.level, .unavailable)
    }

    @MainActor
    func testStoreRetainsStaleSourceInventoryAndCompositeIDsAcrossRefresh() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(inventoryExecution(home: codex.home, serverName: "web")), .success(inventoryExecution(home: codex.home, serverName: "web"))],
            parall.id: [.success(inventoryExecution(home: parall.home, serverName: "web")), .failure(MockFailure.offline)],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex, parall])
        )

        await store.loadInventory(force: true)
        XCTAssertEqual(store.inventory.servers.count, 2)
        XCTAssertEqual(Set(store.inventory.servers.map(\.id)).count, 2)

        await store.loadInventory(force: true)
        XCTAssertEqual(store.inventory.servers.count, 2, "last successful Parall inventory should remain as stale evidence")
        XCTAssertEqual(store.sourceStates.first(where: { $0.origin == parall })?.phase, .stale)
        XCTAssertEqual(store.healthSummary.level, .degraded)
    }

    @MainActor
    func testStoreLoadsOriginsConcurrentlyButAppliesResultsInOriginOrder() async throws {
        let service = ConcurrentOriginCoordinatorService(
            results: [
                codex.id: inventoryExecution(home: codex.home, serverName: "codex-server"),
                parall.id: inventoryExecution(home: parall.home, serverName: "parall-server"),
            ],
            delays: [codex.id: .milliseconds(80), parall.id: .milliseconds(10)]
        )
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [parall, codex])
        )

        await store.loadInventory(force: true)

        let evidence = await service.concurrencyEvidence()
        XCTAssertEqual(evidence.maximumInFlight, 2)
        XCTAssertEqual(evidence.completionOrder, [parall.id, codex.id])
        XCTAssertEqual(store.sourceStates.map(\.origin.id), [codex.id, parall.id])
        XCTAssertEqual(store.sourceStates.map(\.origin.statePath), ["\(codex.home)/state.json", "\(parall.home)/state.json"])
        XCTAssertEqual(store.inventory.servers.map(\.name), ["codex-server", "parall-server"])
        XCTAssertEqual(store.inventory.servers.compactMap { $0.origin?.id }, [codex.id, parall.id])
        XCTAssertTrue(store.capabilityStates.allSatisfy { $0.phase == .available })
        XCTAssertEqual(
            store.capabilityStates.map { "\($0.origin.id)|\($0.capability.rawValue)" },
            [codex, parall].flatMap { origin in
                CoordinatorCapability.allCases.map { "\(origin.id)|\($0.rawValue)" }
            }
        )
    }

    @MainActor
    func testDockerActionsRouteToTheOnlySidecarOwningHome() async throws {
        let unowned = dockerInventoryExecution(home: codex.home, metadataSource: "none", project: nil)
        let owned = dockerInventoryExecution(home: parall.home, metadataSource: "coordinator_sidecar", project: "/repo")
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(unowned)],
            parall.id: [.success(owned), .success(owned), .failure(.offline)],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex, parall])
        )
        await store.loadInventory()
        let container = try XCTUnwrap(store.inventory.docker.containers.first)
        XCTAssertEqual(container.origin?.id, parall.id)
        XCTAssertNil(container.ownershipError)

        store.restartDocker(container)
        try await Task.sleep(for: .milliseconds(50))
        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.last?.0.id, parall.id)
        XCTAssertEqual(calls.last?.1.prefix(2), ["docker", "restart"])
    }

    @MainActor
    func testConflictingSidecarOwnershipDisablesContainerIdentity() async throws {
        let left = dockerInventoryExecution(home: codex.home, metadataSource: "coordinator_sidecar", project: "/left")
        let right = dockerInventoryExecution(home: parall.home, metadataSource: "coordinator_sidecar", project: "/right")
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(left), .success(left)],
            parall.id: [.success(right), .success(right)],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex, parall])
        )
        await store.loadInventory()
        let container = try XCTUnwrap(store.inventory.docker.containers.first)
        XCTAssertNil(container.origin)
        XCTAssertNil(container.resourceIdentity)
        XCTAssertEqual(container.ownershipCandidates.count, 2)
        XCTAssertEqual(container.ownershipError, "conflicting coordinator-sidecar ownership")
    }

    @MainActor
    func testSuccessfulActionDoesNotErasePartialInventoryWarning() async throws {
        let inventory = inventoryExecution(home: codex.home, serverName: "web", project: "/repo")
        let action = CommandExecution(stdout: "{}", stderr: "", exitStatus: 0)
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(inventory), .success(action), .success(inventory)],
            parall.id: [.failure(.offline), .failure(.offline)],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex, parall])
        )
        store.projectPath = "/repo"
        await store.loadInventory()
        XCTAssertEqual(store.lastErrorTitle, "Inventory incomplete")
        let server = try XCTUnwrap(store.inventory.servers.first)

        store.restart(server)
        try await Task.sleep(for: .milliseconds(100))

        XCTAssertEqual(store.actionResults.values.first?.phase, .succeeded)
        XCTAssertEqual(store.lastErrorTitle, "Inventory incomplete")
        XCTAssertEqual(store.healthSummary.level, .degraded)
    }

    @MainActor
    func testMutatingProjectReportWithUnmetObjectiveIsRetainedAsFailure() async throws {
        let report = CommandExecution(
            stdout: #"{"action":"start","ok":false,"partial":false,"classification":"unhealthy_process","urls":[],"ports":[],"services":[],"health_checks":[],"previous_exit_reasons":[],"logs":[]}"#,
            stderr: "",
            exitStatus: 0
        )
        let service = OriginSequencedCoordinatorService(results: [codex.id: [.success(report)]])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [])
        )
        var server = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"web","name":"web","project":"/repo"}"#.utf8)
        )
        server.origin = codex
        let group = ProjectGroup(id: "repo", name: "Repo", projectPath: "/repo", servers: [server], containers: [], databases: [], usage: nil)
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        store.startProject(group)
        try await Task.sleep(for: .milliseconds(50))

        let action = try XCTUnwrap(store.actionResults.values.first)
        XCTAssertEqual(action.phase, .failed)
        XCTAssertEqual(store.actionIssue?.relatedActionID, action.id)
        XCTAssertEqual(action.failure, "unhealthy_process")
        XCTAssertTrue(action.stdout.contains("unhealthy_process"))
        XCTAssertTrue(store.actionIssue?.details.contains("No runtime changes were applied") == true)
    }

    @MainActor
    func testBulkStopRetainsNonzeroPerItemEvidenceAndNormalizesDatabaseToContainer() async throws {
        let failed = CommandExecution(stdout: "docker-out", stderr: "docker-err", exitStatus: 9, timedOut: true)
        let succeeded = CommandExecution(stdout: "server-out", stderr: "", exitStatus: 0)
        let service = OriginSequencedCoordinatorService(results: [codex.id: [.success(failed), .success(succeeded)]])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [])
        )
        var server = try JSONDecoder().decode(ManagedServer.self, from: Data(#"{"id":"sid","name":"web","project":"/repo","status":"running"}"#.utf8))
        server.origin = codex
        server.coordinatorID = "sid"
        server.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "sid").rawValue
        var container = try JSONDecoder().decode(DockerContainer.self, from: Data(#"{"id":"cid","name":"pg","project":"/repo","status":"Up","metadata_source":"coordinator_sidecar"}"#.utf8))
        container.origin = codex
        var database = container
        database.database = "app"
        store.inventory.servers = [server]
        store.inventory.docker.containers = [container]
        store.inventory.postgres = [database]
        markSourceLoaded(store, origin: codex, resourceCount: 2)

        let serverIdentity = try XCTUnwrap(server.resourceIdentity)
        let databaseIdentity = try XCTUnwrap(database.resourceIdentity)
        let containerIdentity = ResourceIdentity(origin: codex, kind: .docker, nativeID: "cid")
        store.setBulkSelected(databaseIdentity, selected: true)
        store.setBulkSelected(containerIdentity, selected: true)
        store.setBulkSelected(serverIdentity, selected: true)
        XCTAssertEqual(store.bulkSelection.selected.filter { $0.kind == .docker }.count, 1)

        let plan = try XCTUnwrap(store.prepareBulkStop())
        XCTAssertTrue(store.executeBulkStop(planID: plan.id, confirmation: plan.confirmationText))
        try await Task.sleep(for: .milliseconds(100))

        let bulk = try XCTUnwrap(store.latestBulkActionResult)
        XCTAssertEqual(bulk.succeededCount, 1)
        XCTAssertEqual(bulk.failedCount, 1)
        let failedResult = try XCTUnwrap(bulk.results.values.first(where: { $0.phase == .timedOut }))
        XCTAssertEqual(failedResult.exitStatus, 9)
        XCTAssertEqual(failedResult.stdout, "docker-out")
        XCTAssertEqual(failedResult.stderr, "docker-err")
    }

    func testUnhealthyResourceAndFailedActionAreVisibleInHealth() {
        let now = Date(timeIntervalSince1970: 100)
        let request = ActionRequest(kind: .restartServer, title: "Restart web", resource: .init(origin: codex, kind: .server, nativeID: "web"))
        let failed = RetainedActionResult(request: request, phase: .failed, queuedAt: now, startedAt: now, finishedAt: now, exitStatus: 1, stdout: "", stderr: "boom", failure: "boom")
        let summary = HealthSummary.reduce(
            sources: [.init(origin: codex, phase: .loaded, checkedAt: now, resourceCount: 1)],
            resourceSignals: [.init(identity: request.resource!, level: .unhealthy, reason: "health check failed")],
            actions: [failed],
            now: now
        )
        XCTAssertEqual(summary.level, .unhealthy)
        XCTAssertEqual(summary.failedActionCount, 1)
        XCTAssertEqual(summary.unhealthyResourceCount, 1)
    }

    func testActionResultRetainsRealOutputAndLeaseValue() throws {
        let data = #"{"id":"lease-123","port":4317,"project":"/repo","status":"active","expires_at_iso":"2026-07-10T15:00:00Z"}"#.data(using: .utf8)!
        let lease = try JSONDecoder().decode(LeaseCommandPayload.self, from: data)
        let result = LeaseActionResult(origin: codex, payload: lease)
        XCTAssertEqual(result.port, 4317)
        XCTAssertEqual(result.leaseID, "lease-123")

        let action = RetainedActionResult(
            request: .init(kind: .dockerLogs, title: "Logs", resource: .init(origin: codex, kind: .docker, nativeID: "db")),
            phase: .succeeded,
            queuedAt: Date(),
            startedAt: Date(),
            finishedAt: Date(),
            exitStatus: 0,
            stdout: "real stdout",
            stderr: "real stderr"
        )
        XCTAssertEqual(action.stdout, "real stdout")
        XCTAssertEqual(action.stderr, "real stderr")
    }

    func testProjectRuntimeReportDecodingRetainsPartialEvidenceButRejectsPlainErrorJSON() throws {
        let partial = try JSONDecoder().decode(
            ProjectRuntimeReport.self,
            from: Data(#"{"action":"stop","project":"/repo","ok":false,"partial":true,"action_errors":[{"name":"compose","error":"docker unavailable"}]}"#.utf8)
        )
        XCTAssertTrue(partial.urls.isEmpty)
        XCTAssertTrue(partial.services.isEmpty)
        XCTAssertEqual(partial.partial, true)
        XCTAssertEqual(partial.actionErrors?.first?.error, "docker unavailable")

        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ProjectRuntimeReport.self,
                from: Data(#"{"error":"docker unavailable"}"#.utf8)
            )
        )
    }

    @MainActor
    func testActionResultCopyDetailsAreTypedAndPreserveFailureEvidence() {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        let now = Date(timeIntervalSince1970: 100)
        let result = RetainedActionResult(
            request: .init(kind: .restartServer, title: "Restart web", resource: .init(origin: codex, kind: .server, nativeID: "web")),
            phase: .failed,
            queuedAt: now,
            startedAt: now,
            finishedAt: now,
            exitStatus: 1,
            stdout: "partial output",
            stderr: "connection refused",
            failure: "health check failed",
            outputTruncated: true
        )

        let details = store.actionResultDetails(result)
        XCTAssertTrue(details.contains("Action: Restart web"))
        XCTAssertTrue(details.contains("Source: Codex"))
        XCTAssertTrue(details.contains("Exit status: 1"))
        XCTAssertTrue(details.contains("Failure: health check failed"))
        XCTAssertTrue(details.contains("partial output"))
        XCTAssertTrue(details.contains("connection refused"))
        XCTAssertTrue(details.contains("Output was truncated"))

        let unscoped = RetainedActionResult(
            request: .init(kind: .leasePort, title: "Lease port", origin: parall, resource: nil),
            phase: .failed,
            queuedAt: now,
            failure: "no free port"
        )
        XCTAssertTrue(store.actionResultDetails(unscoped).contains("Source: Parall"))

        store.actionResults[result.id] = result
        store.actionIssue = OpsIssue(
            kind: .action,
            title: "Restart failed",
            summary: "health check failed",
            details: "connection refused",
            createdAt: now,
            relatedActionID: nil
        )
        store.dismissActionResult(result)
        XCTAssertNil(store.actionResults[result.id])
        XCTAssertNotNil(store.actionIssue, "dismissing evidence must not erase an unrelated synchronous issue")

        store.actionResults[result.id] = result
        store.actionIssue = OpsIssue(
            kind: .action,
            title: "Restart failed",
            summary: "health check failed",
            details: "connection refused",
            createdAt: now,
            relatedActionID: result.id
        )
        store.dismissActionResult(result)
        XCTAssertNil(store.actionIssue, "dismissing matching evidence may clear its linked issue")

        let running = RetainedActionResult(
            request: .init(kind: .restartServer, title: "Restart web", resource: .init(origin: codex, kind: .server, nativeID: "web")),
            phase: .running,
            queuedAt: now
        )
        store.actionResults[running.id] = running
        store.dismissActionResult(running)
        XCTAssertNotNil(store.actionResults[running.id], "running evidence cannot be dismissed before it reaches a terminal phase")
    }

    func testNewestStrongBackupRequiresExactDatabaseIdentity() {
        let target = DatabaseIdentity(origin: codex, container: "pg", database: "app", containerID: "bbbbbbbbbbbb")
        let wrongHome = BackupRecord(identity: .init(origin: parall, container: "pg", database: "app", containerID: "cid"), path: "/b/wrong", createdAt: Date(timeIntervalSince1970: 300), checksum: .verified, restoreTest: .passed)
        let old = BackupRecord(identity: target, path: "/b/old", createdAt: Date(timeIntervalSince1970: 100), checksum: .verified, restoreTest: .passed)
        let weakNew = BackupRecord(identity: target, path: "/b/weak", createdAt: Date(timeIntervalSince1970: 400), checksum: .verified, restoreTest: .notRun)
        let newestStrong = BackupRecord(identity: target, path: "/b/new", createdAt: Date(timeIntervalSince1970: 200), checksum: .verified, restoreTest: .passed)

        XCTAssertEqual(newestVerifiedBackup(for: target, in: [wrongHome, old, weakNew, newestStrong])?.path, "/b/new")
        let recreated = DatabaseIdentity(origin: codex, container: "pg", database: "app", containerID: "different-cid")
        XCTAssertNil(newestVerifiedBackup(for: recreated, in: [newestStrong]), "same-name recreated containers must not inherit old backups")
    }

    func testManifestV2RequiresMatchingChecksumAndStrongRestoreMode() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let artifact = directory.appendingPathComponent("app.dump")
        let manifest = URL(fileURLWithPath: artifact.path + ".manifest.json")
        XCTAssertTrue(FileManager.default.createFile(atPath: artifact.path, contents: Data("dump".utf8)))
        let checksum = try XCTUnwrap(fileSHA256(artifact.path))
        let json = """
        {"schema_version":2,"created_at":"2026-07-10T12:00:00Z","scope":"database","format":"custom","sha256":"\(checksum)","source":{"container":{"name":"pg","id":"cid","image":"postgres:17"},"postgres":{"database":"app","scope":"database"}},"verification":{"verified_at":"2026-07-10T12:01:00Z","mode":"test_restore","scope":"database","sha256":"\(checksum)","ok":true}}
        """
        try Data(json.utf8).write(to: manifest)
        var backup = DatabaseBackup(path: artifact.path, size: 4, modifiedAt: nil, manifest: manifest.path, database: nil, container: nil, format: nil, sha256: nil)
        backup.origin = codex

        let record = try XCTUnwrap(backup.verifiedRecord())
        XCTAssertEqual(record.identity, DatabaseIdentity(origin: codex, container: "pg", database: "app", containerID: "cid"))
        XCTAssertTrue(record.isStronglyVerified)

        try Data("tampered-after-verification".utf8).write(to: artifact)
        XCTAssertEqual(backup.verifiedRecord()?.checksum, .failed)
        XCTAssertFalse(backup.verifiedRecord()?.isStronglyVerified ?? true)
    }

    func testPostgresDiscoveryUsesRealCatalogRowsAndSizes() async throws {
        let fixturePassword = "fixture-super-secret-password"
        let executor = SequencedCommandExecutor(results: [
            .init(stdout: "appuser\napp\n", stderr: "", exitStatus: 0),
            .init(stdout: "analytics\t4096\napp\t8192\n", stderr: "", exitStatus: 0),
        ])
        let discovery = DockerPostgresDiscoveryService(executor: executor)
        let rows = try await discovery.discover(origin: codex, container: "pg", containerID: "cid")

        XCTAssertEqual(rows.map(\.identity.database), ["analytics", "app"])
        XCTAssertEqual(rows.map(\.sizeBytes), [4096, 8192])
        let requests = await executor.capturedRequests()
        let allOutput = await executor.allOutput()
        XCTAssertEqual(requests.count, 2)
        XCTAssertFalse(requests.flatMap(\.arguments).contains { $0.contains(fixturePassword) || $0.contains("POSTGRES_PASSWORD") })
        XCTAssertFalse(rows.map(\.identity.database).contains { $0.contains(fixturePassword) })
        XCTAssertFalse(allOutput.contains(fixturePassword))
        XCTAssertEqual(requests[1].arguments.prefix(3), ["docker", "exec", "pg"])
        XCTAssertTrue(requests[1].arguments.contains { $0.contains("pg_database_size(datname)") })
    }

    func testBulkSelectionOnlyReturnsExplicitResourcesAndRetainsPerItemResults() {
        let web = ResourceIdentity(origin: codex, kind: .server, nativeID: "web")
        let db = ResourceIdentity(origin: codex, kind: .docker, nativeID: "db")
        var selection = BulkSelection()
        selection.select(web)
        XCTAssertEqual(selection.selected, [web])
        XCTAssertFalse(selection.contains(db))

        let result = BulkActionResult(selection: selection, results: [
            web: RetainedActionResult(request: .init(kind: .stopServer, title: "Stop web", resource: web), phase: .succeeded, queuedAt: Date())
        ])
        XCTAssertEqual(result.succeededCount, 1)
        XCTAssertEqual(result.failedCount, 0)
    }

    func testUptimeIsMeasuredOrExplicitlyUnavailable() {
        XCTAssertEqual(UptimeValue(startedAt: Date(timeIntervalSince1970: 10), now: Date(timeIntervalSince1970: 70)), .measured(60))
        XCTAssertEqual(UptimeValue(startedAt: nil, now: Date()), .unavailable("start time unavailable"))
    }

    func testServerUptimeUsesCurrentProcessTimestampNotLogicalRecordAge() throws {
        let legacy = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"web","name":"web","created_at":"2020-01-01T00:00:00Z"}"#.utf8)
        )
        XCTAssertEqual(legacy.uptime(now: Date(timeIntervalSince1970: 100)), .unavailable("start time unavailable"))

        let restarted = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"web","name":"web","created_at":"2020-01-01T00:00:00Z","created_ts":70}"#.utf8)
        )
        XCTAssertEqual(restarted.uptime(now: Date(timeIntervalSince1970: 100)), .measured(30))
    }

    func testPortableSkillLocatorUsesConfiguredRoot() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let script = root.appendingPathComponent("skills/codex-dev-coordinator/scripts/dev_coordinator.py")
        try FileManager.default.createDirectory(at: script.deletingLastPathComponent(), withIntermediateDirectories: true)
        XCTAssertTrue(FileManager.default.createFile(atPath: script.path, contents: Data()))
        defer { try? FileManager.default.removeItem(at: root) }

        let locator = PortableSkillLocator(environment: ["DEVCOORDINATOR_ROOT": root.path], home: "/unused", currentDirectory: "/unused")
        XCTAssertEqual(try locator.scriptPath(for: .coordinator), script.path)
    }

    func testPackagedSkillLocatorPrefersBundledHelperAndKeepsExplicitOverride() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let bundleRoot = root.appendingPathComponent("DevOpsBoard.app/Contents/Resources")
        let bundled = bundleRoot.appendingPathComponent("skills/codex-dev-coordinator/scripts/dev_coordinator.py")
        let home = root.appendingPathComponent("home")
        let installed = home.appendingPathComponent(".codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py")
        let checkout = root.appendingPathComponent("checkout")
        let checkedOut = checkout.appendingPathComponent("skills/codex-dev-coordinator/scripts/dev_coordinator.py")
        let override = root.appendingPathComponent("override")
        let overridden = override.appendingPathComponent("skills/codex-dev-coordinator/scripts/dev_coordinator.py")
        for helper in [bundled, installed, checkedOut, overridden] {
            try FileManager.default.createDirectory(at: helper.deletingLastPathComponent(), withIntermediateDirectories: true)
            XCTAssertTrue(FileManager.default.createFile(atPath: helper.path, contents: Data()))
        }

        let packaged = PortableSkillLocator(
            environment: [:],
            home: home.path,
            currentDirectory: checkout.path,
            bundleResourceRoot: bundleRoot.path
        )
        XCTAssertEqual(try packaged.scriptPath(for: .coordinator), bundled.path)

        let explicitlyOverridden = PortableSkillLocator(
            environment: ["DEVCOORDINATOR_ROOT": override.path],
            home: home.path,
            currentDirectory: checkout.path,
            bundleResourceRoot: bundleRoot.path
        )
        XCTAssertEqual(try explicitlyOverridden.scriptPath(for: .coordinator), overridden.path)
    }

    func testSystemExecutorReportsTimeoutAndOutputTruncationTruthfully() async throws {
        let executor = SystemCommandExecutor()
        let timedOut = try await executor.execute(
            CommandRequest(
                executable: "/usr/bin/env",
                arguments: ["python3", "-c", "import time; time.sleep(1)"],
                timeout: 0.1
            )
        )
        XCTAssertTrue(timedOut.timedOut)

        let truncated = try await executor.execute(
            CommandRequest(
                executable: "/usr/bin/env",
                arguments: ["python3", "-c", "print('x' * 100)"],
                maxOutputBytes: 16
            )
        )
        XCTAssertTrue(truncated.outputTruncated)
        XCTAssertLessThanOrEqual(truncated.stdout.utf8.count, 16)
        XCTAssertNotEqual(truncated.exitStatus, 0)

        let cancellation = Task {
            try await executor.execute(
                CommandRequest(
                    executable: "/usr/bin/env",
                    arguments: ["python3", "-c", "import time; time.sleep(5)"],
                    timeout: 10
                )
            )
        }
        try await Task.sleep(for: .milliseconds(100))
        cancellation.cancel()
        let cancelled = try await cancellation.value
        XCTAssertTrue(cancelled.cancelled)
    }

    func testSystemExecutorSpoolsOnlyToPrivateBoundedFiles() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executor = SystemCommandExecutor(temporaryRoot: root, retainCompletedSpools: true)
        let result = try await executor.execute(
            CommandRequest(
                executable: "/usr/bin/env",
                arguments: ["python3", "-c", "print('x' * 1000000)"],
                maxOutputBytes: 1024
            )
        )
        XCTAssertTrue(result.outputTruncated)
        let directories = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
        let spool = try XCTUnwrap(directories.first)
        let directoryMode = (try FileManager.default.attributesOfItem(atPath: spool.path)[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(directoryMode, 0o700)
        let files = try FileManager.default.contentsOfDirectory(at: spool, includingPropertiesForKeys: nil)
        XCTAssertEqual(files.count, 2)
        var totalSize = 0
        for file in files {
            let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
            totalSize += (attributes[.size] as? NSNumber)?.intValue ?? 0
        }
        XCTAssertLessThanOrEqual(totalSize, 1024)
    }

    func testCommandEnvironmentBuildsLaunchSafePathFromAbsoluteInheritedAndSystemEntries() {
        let environment = CommandEnvironment.resolved(
            inherited: [
                "PATH": "relative:/opt/custom/bin:/usr/bin:/opt/custom/bin:",
                "INHERITED_VALUE": "kept",
            ],
            systemPathsFileContents: "/usr/local/bin\nnot/absolute\n/usr/bin\n",
            pathDirectoryFiles: [
                .init(name: "90-last", contents: "/z/bin\n../unsafe\n"),
                .init(name: "10-first", contents: "/a/bin\n/usr/local/bin\n"),
            ]
        )

        XCTAssertEqual(
            environment["PATH"],
            "/opt/custom/bin:/usr/bin:/usr/local/bin:/a/bin:/z/bin"
        )
        XCTAssertEqual(environment["INHERITED_VALUE"], "kept")
    }

    func testCommandEnvironmentMergeCannotDropLaunchSafePathFromAnyRequest() {
        let merged = CommandEnvironment.merging(
            base: ["PATH": "/usr/local/bin:/usr/bin", "SCOPE": "base"],
            overrides: ["PATH": "/request/bin:relative:/usr/bin", "SCOPE": "request"]
        )

        XCTAssertEqual(merged["PATH"], "/request/bin:/usr/bin:/usr/local/bin")
        XCTAssertEqual(merged["SCOPE"], "request")
    }

    func testSystemExecutorAppliesBaseEnvironmentToRequestsWithoutEnvironmentOverrides() async throws {
        let executor = SystemCommandExecutor(
            baseEnvironment: [
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "CODEX_GUI_PATH_PROBE": "present",
            ]
        )
        let execution = try await executor.execute(
            CommandRequest(executable: "/usr/bin/env", arguments: [])
        )

        XCTAssertEqual(execution.exitStatus, 0)
        let environmentLines = Set(execution.stdout.split(whereSeparator: \.isNewline).map(String.init))
        XCTAssertTrue(environmentLines.contains("CODEX_GUI_PATH_PROBE=present"))
        XCTAssertTrue(environmentLines.contains("PATH=/usr/local/bin:/usr/bin:/bin"))
    }

    @MainActor
    func testDatabaseBackupImmediatelyRunsStrongVerificationForExactTarget() async throws {
        let backupService = RecordingBackupService(results: [
            .init(stdout: #"{"backup":"/repo/.codex-db-backups/app.dump","manifest":"/repo/.codex-db-backups/app.dump.manifest.json","sha256":"abc"}"#, stderr: "", exitStatus: 0),
            .init(stdout: #"{"ok":true,"test_restore":true}"#, stderr: "", exitStatus: 0),
        ])
        let coordinator = OriginSequencedCoordinatorService(results: [:])
        let store = OpsStore(
            coordinatorService: coordinator,
            backupService: backupService,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [])
        )
        var database = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"aaaaaaaaaaaa","name":"pg","project":"/repo","status":"Up"}"#.utf8)
        )
        database.origin = codex
        database.database = "app"
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        store.backupDatabase(container: database)
        try await Task.sleep(for: .milliseconds(100))

        let calls = await backupService.capturedArguments()
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0].suffix(6), ["--container", "pg", "--database", "app", "--expect-container-id", "aaaaaaaaaaaa"])
        XCTAssertEqual(calls[1], ["verify", "--container", "pg", "--database", "app", "--file", "/repo/.codex-db-backups/app.dump", "--expect-container-id", "aaaaaaaaaaaa", "--test-restore"])
        XCTAssertEqual(store.actionResults.values.first?.phase, .succeeded)
    }

    @MainActor
    func testRestoreRequiresExactStrongBackupAndExplicitTargetConfirmation() async throws {
        let backupService = RecordingBackupService(results: [
            .init(
                stdout: #"{"restored":"/backups/app.dump","container":"pg","database":"app","transactional":true,"incoming_verification":{"test_restore":true,"scratch_created":true,"restore_returncode":0},"safety_backup":{"backup":"/backups/safety.dump","manifest":"/backups/safety.dump.manifest.json","sha256":"safety-sha"},"safety_verification":{"test_restore":true,"scratch_created":true,"restore_returncode":0},"restored_catalog_signature":{"tables":2,"rows":7},"container_identity_preflights":[{"phase":"restore selection","expected_id":"aaaaaaaaaaaa","actual_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","match":"unambiguous_standard_short","execution_target":"immutable_full_id"},{"phase":"restore post-incoming preflight","expected_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","actual_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","match":"exact_full","execution_target":"immutable_full_id"},{"phase":"restore final mutation","expected_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","actual_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","match":"exact_full","execution_target":"immutable_full_id"}]}"#,
                stderr: "",
                exitStatus: 0
            )
        ])
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            backupService: backupService,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [])
        )
        let target = DatabaseIdentity(origin: codex, container: "pg", database: "app", containerID: "aaaaaaaaaaaa")
        let strong = BackupRecord(identity: target, path: "/backups/app.dump", createdAt: Date(), checksum: .verified, restoreTest: .passed)
        let weak = BackupRecord(identity: target, path: "/backups/weak.dump", createdAt: Date(), checksum: .unknown, restoreTest: .notRun)
        let wrongContainer = BackupRecord(
            identity: .init(origin: codex, container: "pg", database: "app", containerID: "new-cid"),
            path: "/backups/wrong.dump",
            createdAt: Date(),
            checksum: .verified,
            restoreTest: .passed
        )
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        store.restoreDatabase(target: target, backup: weak, confirmation: store.restoreConfirmation(for: target))
        store.restoreDatabase(target: target, backup: wrongContainer, confirmation: store.restoreConfirmation(for: target))
        store.restoreDatabase(target: target, backup: strong, confirmation: "RESTORE something-else")
        let rejectedCalls = await backupService.capturedArguments()
        XCTAssertEqual(rejectedCalls.count, 0)

        store.restoreDatabase(target: target, backup: strong, confirmation: store.restoreConfirmation(for: target))
        try await Task.sleep(for: .milliseconds(100))
        let calls = await backupService.capturedArguments()
        XCTAssertEqual(calls, [[
            "restore", "--container", "pg", "--database", "app", "--file", "/backups/app.dump",
            "--expect-container-id", "aaaaaaaaaaaa", "--confirm-restore", "--safety-out-dir", "/backups/pre-restore",
        ]])
        XCTAssertEqual(store.actionResults.values.first?.phase, .succeeded)
        XCTAssertTrue(store.actionResults.values.first?.stdout.contains("safety_backup") == true)
        XCTAssertEqual(store.restoreEvidence[target]?.safetyBackupPath, "/backups/safety.dump")
    }

    func testPrivateCoordinatorConfigurationIsPrivateAtomicAndRecoversLastKnownGood() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("configuration.json")
        let store = PrivateCoordinatorConfigurationStore(configurationURL: url)
        let configuration = CoordinatorConfiguration(
            sources: [
                .init(label: "Lab", home: "/tmp/lab-coordinator", enabled: true),
                .init(label: "Disabled", home: "/tmp/disabled-coordinator", enabled: false),
            ],
            refreshPolicy: .interval(seconds: 12)
        )

        try store.save(configuration)

        let directoryMode = (try FileManager.default.attributesOfItem(atPath: root.path)[.posixPermissions] as? NSNumber)?.intValue
        let primaryMode = (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue
        let backupMode = (try FileManager.default.attributesOfItem(atPath: store.lastKnownGoodURL.path)[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(directoryMode, 0o700)
        XCTAssertEqual(primaryMode, 0o600)
        XCTAssertEqual(backupMode, 0o600)
        XCTAssertEqual(store.load().configuration, try configuration.validated())

        try Data("corrupt-primary".utf8).write(to: url)
        let recovered = store.load()
        XCTAssertEqual(recovered.configuration, try configuration.validated())
        XCTAssertTrue(recovered.usedLastKnownGood)
        XCTAssertNotNil(recovered.warning)

        try store.save(configuration)
        try FileManager.default.removeItem(at: url)
        let missingRecovered = store.load()
        XCTAssertEqual(missingRecovered.configuration, try configuration.validated())
        XCTAssertTrue(missingRecovered.usedLastKnownGood)

        try Data("corrupt-primary".utf8).write(to: url)
        try Data("corrupt-backup".utf8).write(to: store.lastKnownGoodURL)
        let failed = store.load()
        XCTAssertNil(failed.configuration)
        XCTAssertFalse(failed.usedLastKnownGood)
        XCTAssertTrue(failed.warning?.contains("last-known-good copy are invalid") == true)
    }

    func testCoordinatorConfigurationValidationRejectsInvalidShapesAndAcceptsManualPolicy() throws {
        let duplicate = CoordinatorConfiguration(
            sources: [
                .init(label: "A", home: "/tmp/same/../source"),
                .init(label: "B", home: "/tmp/source"),
            ]
        )
        XCTAssertThrowsError(try duplicate.validated())
        XCTAssertThrowsError(try CoordinatorConfiguration(refreshPolicy: .interval(seconds: 0.5)).validated())
        XCTAssertThrowsError(try CoordinatorConfiguration(sources: [.init(label: "Relative", home: "relative/path")]).validated())
        XCTAssertNoThrow(try CoordinatorConfiguration(refreshPolicy: .manual()).validated())
    }

    @MainActor
    func testConfiguredOriginIsLoadedEvenWhenAutomaticDiscoveryDoesNotFindIt() async throws {
        let custom = CoordinatorOrigin(label: "Custom", home: "/tmp/custom-coordinator")
        let configuration = CoordinatorConfiguration(
            sources: [.init(label: custom.label, home: custom.home)],
            refreshPolicy: .manual()
        )
        let service = OriginSequencedCoordinatorService(results: [
            custom.id: [.success(inventoryExecution(home: custom.home, serverName: "web"))]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore(configuration: configuration)
        )

        await store.loadInventory()

        XCTAssertEqual(store.sourceStates.map(\.origin.id), [custom.id])
        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertNil(store.refreshIntervalSeconds)
        let configuredCalls = await service.capturedCalls()
        XCTAssertEqual(configuredCalls.first?.0.id, custom.id)
    }

    @MainActor
    func testDisabledConfiguredOriginSuppressesTheMatchingAutomaticSource() async throws {
        let configuration = CoordinatorConfiguration(
            sources: [.init(label: codex.label, home: codex.home, enabled: false)],
            refreshPolicy: .manual()
        )
        let service = OriginSequencedCoordinatorService(results: [:])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(configuration: configuration)
        )

        await store.loadInventory()

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 0)
        XCTAssertTrue(store.sourceStates.isEmpty)
        XCTAssertEqual(store.presentationSnapshot.level, .unavailable)
    }

    @MainActor
    func testRefreshPolicyThrottlesAutomaticPollingButExplicitRefreshIsImmediate() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(inventoryExecution(home: codex.home, serverName: "first")),
                .success(inventoryExecution(home: codex.home, serverName: "second")),
            ]
        ])
        let configuration = CoordinatorConfiguration(refreshPolicy: .interval(seconds: 60))
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(configuration: configuration)
        )

        await store.loadInventory()
        await store.loadInventory()
        let throttledCalls = await service.capturedCalls()
        XCTAssertEqual(throttledCalls.count, 1)
        XCTAssertEqual(store.inventory.servers.first?.name, "first")

        await store.loadInventory(force: true)
        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(store.inventory.servers.first?.name, "second")
    }

    @MainActor
    func testDockerCapabilityFailureDoesNotMakeCoordinatorSourceStaleOrBlockServerAndLease() async throws {
        let unavailable = inventoryWithDockerUnavailableExecution(home: codex.home)
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(unavailable),
                .success(.init(stdout: "{}", stderr: "", exitStatus: 0)),
                .success(unavailable),
                .success(.init(stdout: #"{"id":"lease-5555","port":5555,"project":"/repo","status":"active","expires_at_iso":"2099-01-01T00:00:00Z"}"#, stderr: "", exitStatus: 0)),
                .success(unavailable),
            ]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore()
        )
        store.projectPath = "/repo"

        await store.loadInventory(force: true)
        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .docker }?.phase,
            .unavailable
        )
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .database }?.phase,
            .unavailable
        )
        XCTAssertEqual(store.presentationSnapshot.level, .degraded)
        let server = try XCTUnwrap(store.inventory.servers.first)
        XCTAssertTrue(
            store.mutationAvailability(
                kind: .restartServer,
                origin: codex,
                resource: server.resourceIdentity
            ).isAllowed
        )
        XCTAssertTrue(
            store.mutationAvailability(kind: .leasePort, origin: codex, resource: nil).isAllowed
        )
        XCTAssertEqual(
            store.mutationAvailability(
                kind: .restartDocker,
                origin: codex,
                resource: ResourceIdentity(origin: codex, kind: .docker, nativeID: "docker-id")
            ).blockKind,
            .unavailableCapability
        )
        XCTAssertEqual(
            store.mutationAvailability(
                kind: .backupDatabase,
                origin: codex,
                resource: ResourceIdentity(origin: codex, kind: .database, nativeID: "docker-id|app")
            ).blockKind,
            .unavailableCapability
        )

        store.restart(server)
        try await Task.sleep(for: .milliseconds(80))
        store.leasePort()
        try await Task.sleep(for: .milliseconds(80))

        var retainedDocker = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"docker-id","name":"web-container","project":"/repo","status":"Up"}"#.utf8)
        )
        retainedDocker.origin = codex
        store.restartDocker(retainedDocker)
        try await Task.sleep(for: .milliseconds(30))

        let calls = await service.capturedCalls()
        XCTAssertTrue(calls.contains { $0.1.prefix(2) == ["server", "restart"] })
        XCTAssertTrue(calls.contains { $0.1.prefix(2) == ["port", "lease"] })
        XCTAssertFalse(calls.contains { $0.1.prefix(2) == ["docker", "restart"] })
        XCTAssertEqual(store.latestLeaseResult?.port, 5555)
        XCTAssertTrue(store.lastError?.localizedCaseInsensitiveContains("Docker") == true)
    }

    @MainActor
    func testDockerBackedProjectMutationRequiresDockerButStatusAndServerOnlyProjectsRemainAvailable() throws {
        let service = OriginSequencedCoordinatorService(results: [:])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        var server = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"server-id","name":"web","project":"/repo","status":"running"}"#.utf8)
        )
        server.origin = codex
        var container = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"container-id","name":"db","project":"/repo","status":"Up","metadata_source":"coordinator_sidecar"}"#.utf8)
        )
        container.origin = codex
        markSourceLoaded(store, origin: codex, resourceCount: 2)
        store.capabilityStates = store.capabilityStates.map { state in
            guard state.capability == .docker else { return state }
            return CoordinatorCapabilityState(
                origin: state.origin,
                capability: state.capability,
                phase: .unavailable,
                checkedAt: state.checkedAt,
                error: "Docker executable unavailable"
            )
        }

        let dockerBacked = ProjectGroup(
            id: "repo",
            name: "Repo",
            projectPath: "/repo",
            servers: [server],
            containers: [container],
            databases: [],
            usage: nil
        )
        let serverOnly = ProjectGroup(
            id: "server-only",
            name: "Server only",
            projectPath: "/server-only",
            servers: [server],
            containers: [],
            databases: [],
            usage: nil
        )
        let knownDockerWithoutCurrentContainers = ProjectGroup(
            id: "known-docker",
            name: "Known Docker",
            projectPath: "/known-docker",
            servers: [server],
            containers: [],
            databases: [],
            usage: nil
        )
        store.projectRuntimeReports[knownDockerWithoutCurrentContainers.id] = try JSONDecoder().decode(
            ProjectRuntimeReport.self,
            from: Data(#"{"action":"status","project":"/known-docker","ok":false,"services":[{"type":"compose","name":"web-stack"}]}"#.utf8)
        )

        XCTAssertEqual(
            store.projectMutationAvailability(kind: .projectStop, group: dockerBacked).blockKind,
            .unavailableCapability
        )
        XCTAssertEqual(
            store.projectMutationAvailability(kind: .projectRestart, group: knownDockerWithoutCurrentContainers).blockKind,
            .unavailableCapability
        )
        XCTAssertTrue(store.projectMutationAvailability(kind: .projectStatus, group: dockerBacked).isAllowed)
        XCTAssertTrue(store.projectMutationAvailability(kind: .projectStop, group: serverOnly).isAllowed)

        store.stopProject(dockerBacked)
        XCTAssertTrue(store.actionResults.isEmpty)
    }

    @MainActor
    func testNonzeroProjectActionRetainsPartialEvidenceAndAlwaysRefreshesInventory() async throws {
        let partialReport = CommandExecution(
            stdout: #"{"action":"stop","ok":false,"partial":true,"classification":"missing_dependency","classifications":["missing_dependency"],"project":"/repo","urls":[],"ports":[],"services":[],"health_checks":[],"previous_exit_reasons":[],"logs":[],"action_errors":[{"name":"compose","classification":"missing_dependency","error":"docker unavailable after server stop"}]}"#,
            stderr: "docker unavailable after server stop",
            exitStatus: 17
        )
        let refreshed = inventoryExecution(home: codex.home, serverName: "after-refresh", project: "/repo")
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(partialReport), .success(refreshed)]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore()
        )
        var server = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"server-id","name":"before","project":"/repo","status":"running"}"#.utf8)
        )
        server.origin = codex
        store.inventory.servers = [server]
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let group = ProjectGroup(
            id: "repo",
            name: "Repo",
            projectPath: "/repo",
            servers: [server],
            containers: [],
            databases: [],
            usage: nil
        )

        store.stopProject(group)
        try await waitUntil {
            store.actionResults.values.first?.phase == .failed
                && store.inventory.servers.first?.name == "after-refresh"
        }

        let result = try XCTUnwrap(store.actionResults.values.first)
        XCTAssertEqual(result.exitStatus, 17)
        XCTAssertEqual(result.stdout, partialReport.stdout)
        XCTAssertEqual(result.stderr, partialReport.stderr)
        XCTAssertEqual(store.projectRuntimeReports[group.id]?.partial, true)
        XCTAssertTrue(store.actionIssue?.summary.contains("partial changes applied") == true)
        XCTAssertTrue(store.actionIssue?.details.contains("Partial changes were applied") == true)
        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 2, "the failed project command must be followed by an inventory refresh")
        XCTAssertEqual(calls.last?.1 ?? [], ["inventory"])
    }

    @MainActor
    func testThrownProjectActionFailureStillRefreshesInventory() async throws {
        let refreshed = inventoryExecution(home: codex.home, serverName: "refreshed-after-throw", project: "/repo")
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.failure(.offline), .success(refreshed)]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore()
        )
        var server = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"server-id","name":"before","project":"/repo","status":"running"}"#.utf8)
        )
        server.origin = codex
        store.inventory.servers = [server]
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let group = ProjectGroup(
            id: "repo",
            name: "Repo",
            projectPath: "/repo",
            servers: [server],
            containers: [],
            databases: [],
            usage: nil
        )

        store.stopProject(group)
        try await waitUntil {
            store.actionResults.values.first?.phase == .failed
                && store.inventory.servers.first?.name == "refreshed-after-throw"
        }

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls.last?.1 ?? [], ["inventory"])
    }

    @MainActor
    func testPresentationKeepsInventoryTruthAfterDismissibleActionErrorIsCleared() throws {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        store.sourceStates = [.init(origin: codex, phase: .stale, checkedAt: Date(), resourceCount: 1, error: "offline")]
        let unowned = try JSONDecoder().decode(ManagedServer.self, from: Data(#"{"id":"web","name":"web","status":"running"}"#.utf8))

        store.restart(unowned)
        XCTAssertNotNil(store.actionIssue)
        XCTAssertEqual(store.presentationSnapshot.level, .unhealthy)

        store.dismissActionIssue()
        XCTAssertNil(store.actionIssue)
        XCTAssertEqual(store.presentationSnapshot.level, .degraded)
        XCTAssertFalse(store.presentationSnapshot.health.isComplete)

        let nominal = HealthSummary.reduce(
            sources: [.init(origin: codex, phase: .loaded, checkedAt: Date(), resourceCount: 1)],
            resourceSignals: [], actions: [], now: Date()
        )
        let configurationIssue = OpsIssue(
            kind: .configuration,
            title: "Configuration invalid",
            summary: "Using last-known-good",
            details: "bad json",
            createdAt: Date()
        )
        XCTAssertEqual(
            OpsPresentationSnapshot.reduce(
                health: nominal,
                sources: [.init(origin: codex, phase: .loaded, checkedAt: Date(), resourceCount: 1)],
                inventoryIssue: configurationIssue,
                actionIssue: nil
            ).level,
            .degraded
        )
    }

    @MainActor
    func testStaleSourceBlocksEveryMutationFamilyWithZeroExternalCalls() async throws {
        let coordinator = OriginSequencedCoordinatorService(results: [:])
        let backupService = RecordingBackupService(results: [])
        let store = OpsStore(
            coordinatorService: coordinator,
            backupService: backupService,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        var server = try JSONDecoder().decode(ManagedServer.self, from: Data(#"{"id":"sid","name":"web","project":"/repo","status":"running"}"#.utf8))
        server.origin = codex
        server.coordinatorID = "sid"
        server.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "sid").rawValue
        var container = try JSONDecoder().decode(DockerContainer.self, from: Data(#"{"id":"redis-id","name":"cache","project":"/repo","status":"Up","metadata_source":"coordinator_sidecar"}"#.utf8))
        container.origin = codex
        var database = try JSONDecoder().decode(DockerContainer.self, from: Data(#"{"id":"cid","name":"pg","project":"/repo","status":"Up","metadata_source":"coordinator_sidecar"}"#.utf8))
        database.origin = codex
        database.database = "app"
        store.inventory.servers = [server]
        store.inventory.docker.containers = [container]
        store.inventory.postgres = [database]
        store.sourceStates = [.init(origin: codex, phase: .stale, checkedAt: Date(), resourceCount: 3, error: "refresh failed")]
        let group = ProjectGroup(id: "repo", name: "Repo", projectPath: "/repo", servers: [server], containers: [container], databases: [database], usage: nil)
        let target = try XCTUnwrap(database.databaseIdentity)
        let backup = BackupRecord(identity: target, path: "/backups/app.dump", createdAt: Date(), checksum: .verified, restoreTest: .passed)

        store.restart(server)
        store.restartDocker(container)
        store.startProject(group)
        store.backupDatabase(container: database)
        store.restoreDatabase(target: target, backup: backup, confirmation: store.restoreConfirmation(for: target))
        store.setBulkSelected(try XCTUnwrap(server.resourceIdentity), selected: true)
        XCTAssertNil(store.prepareBulkStop())
        try await Task.sleep(for: .milliseconds(30))

        let blockedCoordinatorCalls = await coordinator.capturedCalls()
        let blockedBackupCalls = await backupService.capturedArguments()
        XCTAssertEqual(blockedCoordinatorCalls.count, 0)
        XCTAssertEqual(blockedBackupCalls.count, 0)
        XCTAssertEqual(store.mutationAvailability(kind: .stopServer, origin: codex, resource: server.resourceIdentity).blockKind, .staleSource)
        store.sourceStates = [.init(origin: codex, phase: .failed, checkedAt: Date(), error: "denied")]
        XCTAssertEqual(store.mutationAvailability(kind: .stopServer, origin: codex, resource: server.resourceIdentity).blockKind, .failedSource)
        store.sourceStates = []
        XCTAssertEqual(store.mutationAvailability(kind: .stopServer, origin: codex, resource: server.resourceIdentity).blockKind, .unknownSource)
    }

    @MainActor
    func testLoadedSourceAllowsOneActionAndBlocksOnlyTheDuplicate() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(.init(stdout: "{}", stderr: "", exitStatus: 0))]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        var server = try JSONDecoder().decode(ManagedServer.self, from: Data(#"{"id":"sid","name":"web","project":"/repo","status":"running"}"#.utf8))
        server.origin = codex
        server.coordinatorID = "sid"
        server.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "sid").rawValue
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        store.restart(server)
        store.restart(server)
        try await Task.sleep(for: .milliseconds(80))

        let duplicateCalls = await service.capturedCalls()
        XCTAssertEqual(duplicateCalls.count, 1)
        XCTAssertEqual(store.actionResults.count, 1)
        XCTAssertEqual(store.actionResults.values.first?.phase, .succeeded)
    }

    @MainActor
    func testBulkStopRequiresExactPlanAndRejectsChangedStateWithoutCalls() async throws {
        let service = OriginSequencedCoordinatorService(results: [:])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        var server = try JSONDecoder().decode(ManagedServer.self, from: Data(#"{"id":"sid","name":"web","project":"/repo","status":"running"}"#.utf8))
        server.origin = codex
        server.coordinatorID = "sid"
        server.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "sid").rawValue
        store.inventory.servers = [server]
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        store.setBulkSelected(try XCTUnwrap(server.resourceIdentity), selected: true)
        let plan = try XCTUnwrap(store.prepareBulkStop())

        XCTAssertFalse(store.executeBulkStop(planID: plan.id, confirmation: "STOP EVERYTHING"))
        let callsAfterWrongConfirmation = await service.capturedCalls()
        XCTAssertEqual(callsAfterWrongConfirmation.count, 0)

        store.inventory.servers[0].status = "stopped"
        XCTAssertFalse(store.executeBulkStop(planID: plan.id, confirmation: plan.confirmationText))
        let callsAfterChangedState = await service.capturedCalls()
        XCTAssertEqual(callsAfterChangedState.count, 0)
        XCTAssertNil(store.latestBulkActionResult)
    }

    @MainActor
    func testBulkStopMaximumIsFailClosed() async throws {
        let service = OriginSequencedCoordinatorService(results: [:])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 51)
        for index in 0...OpsStore.bulkStopMaximumItems {
            var server = try JSONDecoder().decode(ManagedServer.self, from: Data("{\"id\":\"s\(index)\",\"name\":\"web-\(index)\",\"project\":\"/repo\",\"status\":\"running\"}".utf8))
            server.origin = codex
            server.coordinatorID = "s\(index)"
            server.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "s\(index)").rawValue
            store.inventory.servers.append(server)
            store.setBulkSelected(try XCTUnwrap(server.resourceIdentity), selected: true)
        }

        XCTAssertNil(store.prepareBulkStop())
        let oversizedCalls = await service.capturedCalls()
        XCTAssertEqual(oversizedCalls.count, 0)
        XCTAssertTrue(store.lastError?.contains("at most") == true)
    }

    @MainActor
    func testReleaseLeaseUsesOwningSourceAndRetainsReleasedState() async throws {
        let release = CommandExecution(stdout: #"{"released":true}"#, stderr: "", exitStatus: 0)
        let inventory = inventoryExecution(home: codex.home, serverName: "web")
        let service = OriginSequencedCoordinatorService(results: [codex.id: [.success(release), .success(inventory)]])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let payload = try JSONDecoder().decode(
            LeaseCommandPayload.self,
            from: Data(#"{"id":"lease-123","port":4317,"project":"/repo","status":"active","expires_at_iso":"2099-01-01T00:00:00Z"}"#.utf8)
        )
        let lease = LeaseActionResult(origin: codex, payload: payload)
        store.latestLeaseResult = lease
        store.leaseResults[lease.identity] = lease

        store.releaseLease(lease)
        try await Task.sleep(for: .milliseconds(120))

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.first?.0.id, codex.id)
        XCTAssertEqual(
            calls.first?.1,
            [
                "port", "release",
                "--lease-id", "lease-123",
                "--agent", NSUserName(),
                "--project", "/repo",
            ]
        )
        XCTAssertEqual(store.latestLeaseResult?.phase, .released)
        XCTAssertEqual(store.leaseResults[lease.identity]?.status, "released")

        store.dismissLatestLeaseResult()
        XCTAssertNil(store.latestLeaseResult)
        XCTAssertEqual(store.leaseResults[lease.identity]?.status, "released", "dismissing the card must not erase retained lease evidence")
    }

    @MainActor
    func testDiscoveredInventoryLeaseBecomesManageableWithoutSessionCreation() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(inventoryWithLeaseExecution(home: codex.home))]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore()
        )

        await store.loadInventory(force: true)

        let lease = try XCTUnwrap(store.manageableLeaseResults.first)
        XCTAssertEqual(lease.leaseID, "existing-lease")
        XCTAssertEqual(lease.port, 4317)
        XCTAssertEqual(lease.project, "/repo")
        XCTAssertEqual(lease.phase, .active)
        XCTAssertNil(store.latestLeaseResult, "inventory discovery must not pretend the lease was just created")
        XCTAssertTrue(store.prepareStartDraft(using: lease))
        XCTAssertEqual(store.startDraft.origin?.id, codex.id)
        XCTAssertEqual(store.startDraft.preferredPort, "4317")

        let releasing = RetainedActionResult(
            request: .init(
                kind: .releasePort,
                title: "Release",
                origin: codex,
                resource: lease.identity,
                leaseID: lease.leaseID
            ),
            phase: .running,
            queuedAt: Date()
        )
        store.actionResults[releasing.id] = releasing
        XCTAssertFalse(store.prepareStartDraft(using: lease), "lease preflight must block a concurrent release")
    }

    @MainActor
    func testBoundLeaseCannotBeStartedAgainOrReleasedDirectly() async throws {
        let service = OriginSequencedCoordinatorService(results: [:])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let discovered = try JSONDecoder().decode(
            PortLease.self,
            from: Data(#"{"id":"bound-lease","port":4317,"agent":"tester","project":"/repo","server_id":"server-1","status":"active","expires_at_iso":"2000-01-01T00:00:00Z"}"#.utf8)
        )
        let lease = LeaseActionResult(origin: codex, lease: discovered, now: Date())

        XCTAssertEqual(lease.managementStatus, "attached", "bound leases remain reserved past their original TTL")
        XCTAssertFalse(lease.canStartServer)
        XCTAssertFalse(lease.canReleaseDirectly)
        XCTAssertFalse(store.prepareStartDraft(using: lease))
        store.releaseLease(lease)
        try await Task.sleep(for: .milliseconds(30))

        let calls = await service.capturedCalls()
        XCTAssertTrue(calls.isEmpty)
        XCTAssertTrue(store.actionIssue?.summary.localizedCaseInsensitiveContains("attached") == true)

        let pending = try JSONDecoder().decode(
            PortLease.self,
            from: Data(#"{"id":"pending-lease","port":4318,"agent":"tester","project":"/repo","purpose":"manual","pending_operation_id":"operation-1","status":"active","expires_at_iso":"2000-01-01T00:00:00Z"}"#.utf8)
        )
        let pendingResult = LeaseActionResult(origin: codex, lease: pending, now: Date())
        XCTAssertEqual(pendingResult.managementStatus, "attaching")
        XCTAssertFalse(pendingResult.canStartServer)
        XCTAssertFalse(pendingResult.canReleaseDirectly)
    }

    @MainActor
    func testScopedRefreshDoesNotMisclassifyOtherProjectLeaseAsReleased() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(inventoryWithLeaseExecution(home: codex.home)),
                .failure(.offline),
                .success(inventoryExecution(home: codex.home, serverName: "other", project: "/other")),
            ]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore()
        )

        await store.loadInventory(force: true)
        let identity = try XCTUnwrap(store.manageableLeaseResults.first?.identity)
        store.projectPath = "/other"
        await store.loadInventory(force: true)
        XCTAssertEqual(store.leaseResults[identity]?.phase, .unavailable)
        await store.loadInventory(force: true)

        XCTAssertEqual(store.leaseResults[identity]?.phase, .active)
        XCTAssertEqual(store.leaseResults[identity]?.status, "active")
    }

    @MainActor
    func testMultiSourceLeaseHonorsExplicitOriginInsteadOfGuessing() async throws {
        let leaseResponse = CommandExecution(
            stdout: #"{"id":"lease-parall","port":4555,"project":"/repo","status":"active","expires_at_iso":"2099-01-01T00:00:00Z"}"#,
            stderr: "",
            exitStatus: 0
        )
        let service = OriginSequencedCoordinatorService(results: [parall.id: [.success(leaseResponse)]])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        let checkedAt = Date(timeIntervalSince1970: 10)
        store.sourceStates = [codex, parall].map {
            .init(origin: $0, phase: .loaded, checkedAt: checkedAt, resourceCount: 0)
        }
        store.capabilityStates = [codex, parall].flatMap { origin in
            CoordinatorCapability.allCases.map {
                .init(origin: origin, capability: $0, phase: .available, checkedAt: checkedAt, error: nil)
            }
        }

        store.prepareLeaseDraft()
        XCTAssertNil(store.leaseOrigin, "multiple loaded sources require an explicit choice")
        store.leaseOrigin = parall
        store.projectPath = "/repo"
        store.leasePort()
        try await Task.sleep(for: .milliseconds(80))

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.first?.0.id, parall.id)
        XCTAssertEqual(calls.first?.1.prefix(2), ["port", "lease"])
        XCTAssertEqual(store.latestLeaseResult?.port, 4555)
    }

    func testEditableRowsKeepStableIdentityAcrossValueChangesAndRemoval() {
        var draft = StartServerDraft()
        let retainedID = draft.argumentRows[1].id
        draft.argumentRows[1].value = "changed"
        draft.argumentRows.removeFirst()
        XCTAssertEqual(draft.argumentRows.first?.id, retainedID)
        XCTAssertEqual(draft.arguments.first, "changed")

        var source = CoordinatorSourceDraftRow(
            configuration: CoordinatorSourceConfiguration(label: "Codex", home: "/tmp/codex")
        )
        let sourceID = source.id
        source.home = "/tmp/codex-updated"
        XCTAssertEqual(source.id, sourceID)
        XCTAssertEqual(source.configuration.home, "/tmp/codex-updated")
    }

    @MainActor
    func testGenericStartClearsEveryLeaseDerivedPortField() throws {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let payload = try JSONDecoder().decode(
            LeaseCommandPayload.self,
            from: Data(#"{"id":"lease-4317","port":4317,"project":"/repo","purpose":"manual","status":"active","expires_at_iso":"2099-01-01T00:00:00Z"}"#.utf8)
        )
        XCTAssertTrue(store.prepareStartDraft(using: LeaseActionResult(origin: codex, payload: payload, actingAgent: NSUserName())))

        store.prepareStartDraft()

        XCTAssertNil(store.startDraft.leaseID)
        XCTAssertEqual(store.startDraft.agent, NSUserName())
        XCTAssertEqual(store.startDraft.range, StartServerDraft.defaultRange)
        XCTAssertEqual(store.startDraft.preferredPort, "")
        XCTAssertEqual(store.startDraft.healthURL, StartServerDraft.defaultHealthURL)
    }

    @MainActor
    func testVisibleActionGatesRejectIncompleteResourceArguments() throws {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 2)

        var server = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"sid","name":"web","status":"running"}"#.utf8)
        )
        server.origin = codex
        server.coordinatorID = "sid"
        server.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "sid").rawValue
        XCTAssertFalse(serverActionAllowed(store, kind: .restartServer, server: server))
        server.project = "/repo"
        XCTAssertTrue(serverActionAllowed(store, kind: .restartServer, server: server))

        var container = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"cid","name":"web","status":"Up"}"#.utf8)
        )
        container.origin = codex
        XCTAssertTrue(dockerActionAllowed(store, kind: .dockerLogs, container: container))
        XCTAssertFalse(dockerActionAllowed(store, kind: .restartDocker, container: container))
        container.project = "/repo"
        XCTAssertTrue(dockerActionAllowed(store, kind: .restartDocker, container: container))
    }

    @MainActor
    func testConflictingMutationsAreBlockedAcrossKindsAndDatabaseContainerIdentity() {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 2)
        let now = Date(timeIntervalSince1970: 100)
        let server = ResourceIdentity(origin: codex, kind: .server, nativeID: "server-1")
        let runningRestart = RetainedActionResult(
            request: .init(kind: .restartServer, title: "Restart", origin: codex, resource: server),
            phase: .running,
            queuedAt: now
        )
        store.actionResults[runningRestart.id] = runningRestart
        XCTAssertEqual(
            store.mutationAvailability(kind: .stopServer, origin: codex, resource: server).blockKind,
            .duplicateAction
        )

        store.actionResults.removeAll()
        let database = ResourceIdentity(origin: codex, kind: .database, nativeID: "container-id/pg/app")
        let backup = RetainedActionResult(
            request: .init(kind: .backupDatabase, title: "Backup", origin: codex, resource: database),
            phase: .running,
            queuedAt: now
        )
        store.actionResults[backup.id] = backup
        let container = ResourceIdentity(origin: codex, kind: .docker, nativeID: "container-id")
        XCTAssertEqual(
            store.mutationAvailability(kind: .stopDocker, origin: codex, resource: container).blockKind,
            .duplicateAction
        )

        store.actionResults.removeAll()
        let project = ResourceIdentity(origin: codex, kind: .project, nativeID: "/repo")
        let projectRestart = RetainedActionResult(
            request: .init(
                kind: .projectRestart,
                title: "Restart project",
                origin: codex,
                resource: project,
                projectPath: "/repo"
            ),
            phase: .running,
            queuedAt: now
        )
        store.actionResults[projectRestart.id] = projectRestart
        XCTAssertEqual(
            store.mutationAvailability(
                kind: .stopServer,
                origin: codex,
                resource: server,
                projectPath: "/repo"
            ).blockKind,
            .duplicateAction
        )
    }

    @MainActor
    func testSourceSelectionsRebindToCurrentOriginValues() {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        let old = CoordinatorOrigin(label: "Old label", home: codex.home)
        let current = CoordinatorOrigin(label: "Current label", home: codex.home, statePath: "/current/state.json")
        markSourceLoaded(store, origin: current, resourceCount: 0)
        store.leaseOrigin = old
        store.startDraft.origin = old

        store.prepareLeaseDraft()
        store.prepareStartDraft()

        XCTAssertEqual(store.leaseOrigin?.label, "Current label")
        XCTAssertEqual(store.leaseOrigin?.statePath, "/current/state.json")
        XCTAssertEqual(store.startDraft.origin?.label, "Current label")
        XCTAssertEqual(store.startDraft.origin?.statePath, "/current/state.json")
    }

    @MainActor
    func testRetainedLeaseRebindsToCurrentSourcePresentation() async throws {
        let old = CoordinatorOrigin(label: "Old label", home: codex.home)
        let current = CoordinatorOrigin(label: "Current label", home: codex.home)
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(inventoryWithLeaseExecution(home: codex.home)),
                .success(inventoryWithLeaseExecution(home: codex.home)),
            ]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: SequencedOriginDiscovery(values: [[old], [current]]),
            configurationStore: StaticConfigurationStore()
        )

        await store.loadInventory(force: true)
        XCTAssertEqual(store.manageableLeaseResults.first?.identity.origin.label, "Old label")
        await store.loadInventory(force: true)
        XCTAssertEqual(store.manageableLeaseResults.first?.identity.origin.label, "Current label")
        XCTAssertEqual(store.manageableLeaseResults.count, 1)
    }

    @MainActor
    func testLeaseBoundStartHookPreservesExactSourcePortAndLeaseID() async throws {
        let service = OriginSequencedCoordinatorService(results: [codex.id: [.success(.init(stdout: "{}", stderr: "", exitStatus: 0))]])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let payload = try JSONDecoder().decode(
            LeaseCommandPayload.self,
            from: Data(#"{"id":"lease-4317","port":4317,"project":"/repo","purpose":"manual","status":"active","expires_at_iso":"2099-01-01T00:00:00Z"}"#.utf8)
        )
        XCTAssertTrue(store.prepareStartDraft(using: LeaseActionResult(origin: codex, payload: payload, actingAgent: NSUserName())))
        store.startDraft.name = "web"
        store.startDraft.executable = "run"
        store.startDraft.arguments = ["--port", "{port}"]

        store.startServer()
        try await Task.sleep(for: .milliseconds(80))

        let leaseStartCalls = await service.capturedCalls()
        let call = try XCTUnwrap(leaseStartCalls.first)
        XCTAssertEqual(call.0.id, codex.id)
        XCTAssertTrue(call.1.containsSubsequence(["--range", "4317-4317", "--preferred", "4317"]))
        XCTAssertTrue(call.1.containsSubsequence(["--lease-id", "lease-4317"]))
        XCTAssertFalse(call.1.contains("--cmd"))
        let argvIndex = try XCTUnwrap(call.1.firstIndex(of: "--argv"))
        guard argvIndex + 1 < call.1.count else {
            XCTFail("--argv must be followed by a JSON value")
            return
        }
        let encodedArgv = Data(call.1[argvIndex + 1].utf8)
        XCTAssertEqual(try JSONDecoder().decode([String].self, from: encodedArgv), ["run", "--port", "{port}"])
    }

    @MainActor
    func testStructuredServerStartPreservesArgumentBoundariesWithoutShellParsing() async throws {
        let service = OriginSequencedCoordinatorService(results: [codex.id: [.success(.init(stdout: "{}", stderr: "", exitStatus: 0))]])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        store.startDraft.origin = codex
        store.startDraft.name = "web"
        store.startDraft.executable = "/usr/bin/env"
        store.startDraft.arguments = ["node", "server.js", "--label", "value with spaces", "literal'quote"]

        store.startServer()
        try await Task.sleep(for: .milliseconds(80))

        let calls = await service.capturedCalls()
        let call = try XCTUnwrap(calls.first)
        XCTAssertFalse(call.1.contains("--cmd"))
        let argvIndex = try XCTUnwrap(call.1.firstIndex(of: "--argv"))
        guard argvIndex + 1 < call.1.count else {
            XCTFail("--argv must be followed by a JSON value")
            return
        }
        let decoded = try JSONDecoder().decode([String].self, from: Data(call.1[argvIndex + 1].utf8))
        XCTAssertEqual(decoded, ["/usr/bin/env", "node", "server.js", "--label", "value with spaces", "literal'quote"])
    }

    @MainActor
    func testStructuredServerStartRejectsEmptyExecutableBeforeCoordinatorCall() async {
        let service = OriginSequencedCoordinatorService(results: [:])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        store.startDraft.origin = codex
        store.startDraft.executable = "   "

        store.startServer()

        let calls = await service.capturedCalls()
        XCTAssertTrue(calls.isEmpty)
        XCTAssertTrue(store.lastError?.contains("executable") == true)
    }

    @MainActor
    func testKeyedLogEvidenceDoesNotOverwriteAndKeepsTimeoutTruth() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(.init(stdout: #"{"returncode":0,"stdout":"alpha","stderr":""}"#, stderr: "", exitStatus: 0)),
                .success(.init(stdout: "partial", stderr: "timed out", exitStatus: 9, timedOut: true, outputTruncated: true)),
            ]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        var alpha = try JSONDecoder().decode(DockerContainer.self, from: Data(#"{"id":"a","name":"alpha","project":"/repo","status":"Up"}"#.utf8))
        var beta = try JSONDecoder().decode(DockerContainer.self, from: Data(#"{"id":"b","name":"beta","project":"/repo","status":"Up"}"#.utf8))
        alpha.origin = codex
        beta.origin = codex
        markSourceLoaded(store, origin: codex, resourceCount: 2)

        store.dockerLogs(alpha)
        try await Task.sleep(for: .milliseconds(50))
        store.dockerLogs(beta)
        try await Task.sleep(for: .milliseconds(80))

        let alphaID = try XCTUnwrap(alpha.resourceIdentity)
        let betaID = try XCTUnwrap(beta.resourceIdentity)
        XCTAssertEqual(store.logEvidence.count, 2)
        XCTAssertEqual(store.logEvidence[alphaID]?.displayText, "alpha")
        XCTAssertEqual(store.logEvidence[alphaID]?.state, .available)
        XCTAssertEqual(store.logEvidence[betaID]?.state, .timedOut)
        XCTAssertEqual(store.logEvidence[betaID]?.stderr, "timed out")
        XCTAssertTrue(store.logEvidence[betaID]?.outputTruncated == true)
    }

    @MainActor
    func testExitZeroRestoreWithoutSafetyEvidenceIsRetainedAsFailure() async throws {
        let incomplete = CommandExecution(
            stdout: #"{"restored":"/backups/app.dump","container":"pg","database":"app","transactional":true,"incoming_verification":{"test_restore":true,"scratch_created":true,"restore_returncode":0},"restored_catalog_signature":{"tables":1}}"#,
            stderr: "",
            exitStatus: 0
        )
        let backupService = RecordingBackupService(results: [incomplete])
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            backupService: backupService,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let target = DatabaseIdentity(origin: codex, container: "pg", database: "app", containerID: "bbbbbbbbbbbb")
        let backup = BackupRecord(identity: target, path: "/backups/app.dump", createdAt: Date(), checksum: .verified, restoreTest: .passed)

        store.restoreDatabase(target: target, backup: backup, confirmation: store.restoreConfirmation(for: target))
        try await Task.sleep(for: .milliseconds(80))

        let action = try XCTUnwrap(store.actionResults.values.first)
        XCTAssertEqual(action.phase, .failed)
        XCTAssertEqual(action.exitStatus, 0)
        XCTAssertTrue(action.stdout.contains("restored_catalog_signature"))
        XCTAssertNil(store.restoreEvidence[target])
        XCTAssertTrue(store.lastError?.contains("safety backup") == true)
        let incompleteRestoreCalls = await backupService.capturedArguments()
        XCTAssertTrue(incompleteRestoreCalls.first?.containsSubsequence(["--expect-container-id", "bbbbbbbbbbbb"]) == true)
    }
}

@MainActor
private func markSourceLoaded(
    _ store: OpsStore,
    origin: CoordinatorOrigin,
    resourceCount: Int,
    checkedAt: Date = Date(timeIntervalSince1970: 10)
) {
    store.sourceStates = [
        .init(origin: origin, phase: .loaded, checkedAt: checkedAt, resourceCount: resourceCount)
    ]
    store.capabilityStates = CoordinatorCapability.allCases.map {
        .init(origin: origin, capability: $0, phase: .available, checkedAt: checkedAt, error: nil)
    }
}

@MainActor
private func waitUntil(
    attempts: Int = 100,
    condition: @MainActor () -> Bool
) async throws {
    for _ in 0..<attempts {
        if condition() { return }
        try await Task.sleep(for: .milliseconds(10))
    }
    throw RuntimeError("Timed out waiting for asynchronous store state")
}

private func inventoryExecution(home: String, serverName: String, project: String? = nil) -> CommandExecution {
    let projectJSON = project.map { ",\"project\":\"\($0)\"" } ?? ""
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":[{"id":"same-native-id","name":"\(serverName)"\(projectJSON),"status":"running","health":{"ok":true,"pid_alive":true}}],"leases":[],"recent_events":[],"docker":{"containers":[],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}
    """
    return CommandExecution(stdout: json, stderr: "", exitStatus: 0)
}

private func inventoryWithLeaseExecution(home: String) -> CommandExecution {
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":[],"leases":[{"id":"existing-lease","port":4317,"agent":"tester","project":"/repo","purpose":"manual","status":"active","expires_at_iso":"2099-01-01T00:00:00Z"}],"recent_events":[],"docker":{"containers":[],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}
    """
    return CommandExecution(stdout: json, stderr: "", exitStatus: 0)
}

private func inventoryWithDockerUnavailableExecution(home: String) -> CommandExecution {
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":[{"id":"server-id","name":"web","project":"/repo","status":"running","health":{"ok":true,"pid_alive":true}}],"leases":[],"recent_events":[],"docker":{"available":false,"error":"Docker daemon unavailable","containers":[],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}
    """
    return CommandExecution(stdout: json, stderr: "", exitStatus: 0)
}

private func dockerInventoryExecution(home: String, metadataSource: String, project: String?) -> CommandExecution {
    let projectJSON = project.map { "\"\($0)\"" } ?? "null"
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"containers":[{"id":"immutable-cid","name":"db","status":"Up","project":\(projectJSON),"metadata_source":"\(metadataSource)"}],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}
    """
    return CommandExecution(stdout: json, stderr: "", exitStatus: 0)
}

private struct StaticOriginDiscovery: CoordinatorOriginDiscovering {
    let values: [CoordinatorOrigin]
    func origins() -> [CoordinatorOrigin] { values }
}

private final class SequencedOriginDiscovery: CoordinatorOriginDiscovering, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [[CoordinatorOrigin]]

    init(values: [[CoordinatorOrigin]]) {
        self.values = values
    }

    func origins() -> [CoordinatorOrigin] {
        lock.lock()
        defer { lock.unlock() }
        guard !values.isEmpty else { return [] }
        if values.count == 1 { return values[0] }
        return values.removeFirst()
    }
}

private struct EmptyDatabaseDiscovery: DatabaseDiscovering {
    func discover(origin: CoordinatorOrigin, container: String, containerID: String?) async throws -> [DiscoveredDatabase] { [] }
}

private enum MockFailure: Error { case offline }

private actor OriginSequencedCoordinatorService: CoordinatorServing {
    private var results: [String: [Result<CommandExecution, MockFailure>]]
    private var calls: [(CoordinatorOrigin, [String])] = []

    init(results: [String: [Result<CommandExecution, MockFailure>]]) { self.results = results }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        calls.append((origin, arguments))
        guard var queue = results[origin.id], !queue.isEmpty else { throw MockFailure.offline }
        let result = queue.removeFirst()
        results[origin.id] = queue
        return try result.get()
    }

    func capturedCalls() -> [(CoordinatorOrigin, [String])] { calls }
}

private actor ConcurrentOriginCoordinatorService: CoordinatorServing {
    private let results: [String: CommandExecution]
    private let delays: [String: Duration]
    private var inFlight = 0
    private var maximumInFlight = 0
    private var completionOrder: [String] = []

    init(results: [String: CommandExecution], delays: [String: Duration]) {
        self.results = results
        self.delays = delays
    }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        guard arguments.first == "inventory", let result = results[origin.id] else {
            throw MockFailure.offline
        }
        inFlight += 1
        maximumInFlight = max(maximumInFlight, inFlight)
        defer { inFlight -= 1 }
        if let delay = delays[origin.id] {
            try await Task.sleep(for: delay)
        }
        completionOrder.append(origin.id)
        return result
    }

    func concurrencyEvidence() -> (maximumInFlight: Int, completionOrder: [String]) {
        (maximumInFlight, completionOrder)
    }
}

private actor RecordingBackupService: BackupServing {
    private var results: [CommandExecution]
    private var arguments: [[String]] = []

    init(results: [CommandExecution]) { self.results = results }

    func execute(origin: CoordinatorOrigin?, arguments: [String]) async throws -> CommandExecution {
        self.arguments.append(arguments)
        guard !results.isEmpty else { throw MockFailure.offline }
        return results.removeFirst()
    }

    func capturedArguments() -> [[String]] { arguments }
}

private actor RecordingCommandExecutor: CommandExecuting {
    private(set) var requests: [CommandRequest] = []
    private let result: CommandExecution

    init(result: CommandExecution) {
        self.result = result
    }

    func execute(_ request: CommandRequest) async throws -> CommandExecution {
        requests.append(request)
        return result
    }

    func capturedRequests() -> [CommandRequest] { requests }
}

private actor SequencedCommandExecutor: CommandExecuting {
    private var results: [CommandExecution]
    private let originalResults: [CommandExecution]
    private var requests: [CommandRequest] = []

    init(results: [CommandExecution]) {
        self.results = results
        self.originalResults = results
    }

    func execute(_ request: CommandRequest) async throws -> CommandExecution {
        requests.append(request)
        guard !results.isEmpty else { throw RuntimeError("no queued command result") }
        return results.removeFirst()
    }

    func capturedRequests() -> [CommandRequest] { requests }
    func allOutput() -> String {
        originalResults.map { $0.stdout + $0.stderr }.joined(separator: "\n")
    }
}

private struct StaticConfigurationStore: CoordinatorConfigurationPersisting {
    let configuration: CoordinatorConfiguration?
    let warning: String?

    init(configuration: CoordinatorConfiguration? = nil, warning: String? = nil) {
        self.configuration = configuration
        self.warning = warning
    }

    func load() -> CoordinatorConfigurationLoadResult {
        CoordinatorConfigurationLoadResult(
            configuration: configuration,
            warning: warning,
            usedLastKnownGood: warning != nil && configuration != nil
        )
    }

    func save(_ configuration: CoordinatorConfiguration) throws {}
}

private extension Array where Element: Equatable {
    func containsSubsequence(_ expected: [Element]) -> Bool {
        guard !expected.isEmpty, expected.count <= count else { return false }
        for start in 0...(count - expected.count) where Array(self[start..<(start + expected.count)]) == expected {
            return true
        }
        return false
    }
}
