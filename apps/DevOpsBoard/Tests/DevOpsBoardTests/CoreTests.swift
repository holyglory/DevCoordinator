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

    func testCoordinatorInventoryUsesDedicatedOutputBudgetWithoutRelaxingOrdinaryCommands() async throws {
        let executor = RecordingCommandExecutor(result: .init(stdout: "{}", stderr: "", exitStatus: 0))
        let service = PythonCoordinatorService(executor: executor, scriptPath: "/repo/coordinator.py")

        _ = try await service.execute(origin: codex, arguments: ["inventory", "--compact-json"])
        _ = try await service.execute(origin: codex, arguments: ["server", "status"])

        let requests = await executor.capturedRequests()
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests[0].maxOutputBytes, 16 * 1_024 * 1_024)
        XCTAssertEqual(requests[1].maxOutputBytes, 1_048_576)
    }

    func testInventoryValueGraphCanCrossTheBackgroundDecodeBoundary() async {
        let inventory = Inventory.empty
        let handedOff = await Task.detached(priority: .userInitiated) {
            inventory
        }.value

        XCTAssertEqual(handedOff, inventory)
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
    func testLogicalServerSelectionSurvivesRepresentativeSourceSwitchAcrossRefreshes() async throws {
        let fixtureRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("server-selection-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: fixtureRoot.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }

        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(inventoryExecution(home: codex.home, serverName: "web", project: fixtureRoot.path))],
            parall.id: [.success(inventoryExecution(home: parall.home, serverName: "web", project: fixtureRoot.path))],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: SequencedOriginDiscovery(values: [[codex], [parall]]),
            configurationStore: StaticConfigurationStore()
        )
        let repository = try XCTUnwrap(RepositoryIdentity(projectPath: fixtureRoot.path))
        let logicalSelectionID = RepositoryLogicalServerIdentity(
            repository: repository,
            serviceName: "web"
        ).id

        await store.loadInventory(force: true)
        let firstRepresentative = try XCTUnwrap(store.filteredServers.first)
        XCTAssertEqual(firstRepresentative.origin, codex)
        store.selectServer(firstRepresentative)
        XCTAssertEqual(store.selectedServerID, logicalSelectionID)

        await store.loadInventory(force: true)

        XCTAssertEqual(store.selectedServerID, logicalSelectionID)
        XCTAssertEqual(store.sidebarSelection, .server(logicalSelectionID))
        let selected = try XCTUnwrap(store.selectedServer)
        XCTAssertEqual(selected.origin, parall)
        XCTAssertEqual(selected.resourceIdentity?.origin, parall)
    }

    @MainActor
    func testDockerSelectionSurvivesRepresentativeSourceSwitchAcrossRefreshes() async throws {
        let fixtureRoot = try selectionRepository(named: "docker-selection")
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(selectionContainerInventoryExecution(
                home: codex.home,
                project: fixtureRoot.path,
                postgres: false
            ))],
            parall.id: [.success(selectionContainerInventoryExecution(
                home: parall.home,
                project: fixtureRoot.path,
                postgres: false
            ))],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: SequencedOriginDiscovery(values: [[codex], [parall]]),
            configurationStore: StaticConfigurationStore()
        )

        await store.loadInventory(force: true)
        let firstRepresentative = try XCTUnwrap(store.inventory.docker.containers.first)
        XCTAssertEqual(firstRepresentative.origin, codex)
        store.selectDocker(firstRepresentative)
        XCTAssertEqual(store.selectedDockerID, "container:immutable-selection-container")

        await store.loadInventory(force: true)

        XCTAssertEqual(store.selectedDockerID, "container:immutable-selection-container")
        XCTAssertEqual(store.sidebarSelection, .docker("container:immutable-selection-container"))
        let selected = try XCTUnwrap(store.selectedDocker)
        XCTAssertEqual(selected.origin, parall)
        XCTAssertEqual(selected.resourceIdentity?.origin, parall)
    }

    @MainActor
    func testDatabaseSelectionSurvivesRepresentativeSourceSwitchAcrossRefreshes() async throws {
        let fixtureRoot = try selectionRepository(named: "database-selection")
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(selectionContainerInventoryExecution(
                home: codex.home,
                project: fixtureRoot.path,
                postgres: true
            ))],
            parall.id: [.success(selectionContainerInventoryExecution(
                home: parall.home,
                project: fixtureRoot.path,
                postgres: true
            ))],
        ])
        let store = OpsStore(
            coordinatorService: service,
            backupService: RecordingBackupService(results: []),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: StaticDatabaseDiscovery(database: "app", sizeBytes: 1_024),
            originDiscovery: SequencedOriginDiscovery(values: [[codex], [parall]]),
            configurationStore: StaticConfigurationStore()
        )

        await store.loadInventory(force: true)
        let firstRepresentative = try XCTUnwrap(store.inventory.postgres.first)
        XCTAssertEqual(firstRepresentative.origin, codex)
        store.selectDatabase(firstRepresentative)
        let logicalSelectionID = "container:immutable-selection-container|database|app"
        XCTAssertEqual(store.selectedDatabaseID, logicalSelectionID)

        await store.loadInventory(force: true)

        XCTAssertEqual(store.selectedDatabaseID, logicalSelectionID)
        XCTAssertEqual(store.sidebarSelection, .database(logicalSelectionID))
        let selected = try XCTUnwrap(store.selectedDatabase)
        XCTAssertEqual(selected.origin, parall)
        XCTAssertEqual(selected.databaseIdentity?.origin, parall)
    }

    @MainActor
    func testThreeSourceRepositoryPublishesOneNevodProjectAndRoutesOneProjectAction() async throws {
        let account = CoordinatorOrigin(label: "Account Codex", home: "/fixtures/multi-source/account")
        let chatGPT = CoordinatorOrigin(label: "Parall ChatGPT", home: "/fixtures/multi-source/chatgpt")
        let codexTT = CoordinatorOrigin(label: "Parall Codex", home: "/fixtures/multi-source/codex")
        let fixtureRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("core-three-source-\(UUID().uuidString)", isDirectory: true)
        let projectURL = fixtureRoot.appendingPathComponent("Nevod", isDirectory: true)
        try FileManager.default.createDirectory(
            at: projectURL.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }
        let project = projectURL.path
        let accountInventory = threeSourceRepositoryInventoryExecution(
            home: account.home,
            project: project,
            includeServers: false,
            sample: 1
        )
        let chatInventory = threeSourceRepositoryInventoryExecution(
            home: chatGPT.home,
            project: project,
            includeServers: false,
            sample: 2
        )
        let codexInventory = threeSourceRepositoryInventoryExecution(
            home: codexTT.home,
            project: project,
            includeServers: true,
            sample: 3
        )
        let successfulStart = CommandExecution(
            stdout: #"{"action":"start","project":"\#(project)","ok":true,"partial":false,"urls":[],"ports":[],"services":[],"health_checks":[],"previous_exit_reasons":[],"logs":[],"action_errors":[]}"#,
            stderr: "",
            exitStatus: 0
        )
        let service = OriginSequencedCoordinatorService(results: [
            account.id: [.success(accountInventory), .success(accountInventory), .success(accountInventory), .success(accountInventory)],
            chatGPT.id: [.success(chatInventory), .success(chatInventory), .success(chatInventory), .success(chatInventory)],
            codexTT.id: [.success(codexInventory), .success(codexInventory), .success(successfulStart), .success(codexInventory), .success(codexInventory)],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [account, chatGPT, codexTT]),
            configurationStore: StaticConfigurationStore()
        )

        await store.loadInventory(force: true)

        let group = try XCTUnwrap(store.projectGroups.first)
        XCTAssertEqual(store.repositoryCatalog.repositories.count, 1)
        XCTAssertEqual(store.projectGroups.count, 1)
        XCTAssertEqual(group.name, "Nevod")
        XCTAssertEqual(group.servers.count, 2)
        XCTAssertEqual(group.usage?.containerCount, 2)
        XCTAssertEqual(group.usage?.memoryBytes, 3_700_000_000)
        XCTAssertEqual(Set(group.observedOrigins), Set([account, chatGPT, codexTT]))
        XCTAssertEqual(group.actionOrigin, codexTT)
        XCTAssertTrue(store.projectMutationAvailability(kind: .projectStart, group: group).isAllowed)

        store.startProject(group)
        try await waitUntil {
            store.actionResults.values.first?.phase == .succeeded
        }
        try await waitUntilAsync {
            await service.capturedCalls().count == 13
        }

        let calls = await service.capturedCalls()
        let projectCalls = calls.filter { $0.1.prefix(2) == ["project", "start"] }
        XCTAssertEqual(projectCalls.count, 1, "one repository action must never fan out once per observing source")
        XCTAssertEqual(projectCalls.first?.0, codexTT)
        XCTAssertEqual(
            projectCalls.first?.1,
            ["project", "start", "--project", project, "--agent", NSUserName()]
        )
        XCTAssertEqual(store.projectGroups.count, 1, "the post-action refresh must preserve canonical repository identity")
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
    func testCatalogOwnershipConflictMakesPublishedHealthNonNominalEvenWithoutResourceIdentity() async throws {
        let fixtureRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("core-docker-conflict-\(UUID().uuidString)", isDirectory: true)
        let leftProject = fixtureRoot.appendingPathComponent("left-owner", isDirectory: true)
        let rightProject = fixtureRoot.appendingPathComponent("right-owner", isDirectory: true)
        try FileManager.default.createDirectory(
            at: leftProject.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: rightProject.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }
        let leftInventory = dockerProjectConflictInventoryExecution(
            home: codex.home,
            project: leftProject.path
        )
        let rightInventory = dockerProjectConflictInventoryExecution(
            home: parall.home,
            project: rightProject.path
        )
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(leftInventory), .success(leftInventory)],
            parall.id: [.success(rightInventory), .success(rightInventory)],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex, parall]),
            configurationStore: StaticConfigurationStore()
        )

        await store.loadInventory(force: true)

        XCTAssertNil(store.inventory.docker.containers.first?.resourceIdentity)
        XCTAssertEqual(store.repositoryCatalog.repositories.flatMap(\.dockerMembershipConflicts).count, 2)
        XCTAssertEqual(store.healthSummary.level, .unhealthy)
        XCTAssertEqual(store.healthSummary.unhealthyResourceCount, 1)
        XCTAssertNotEqual(store.presentationSnapshot.statusTitle, "All systems nominal")

        let conflicted = try XCTUnwrap(store.projectGroups.first(where: \.isRepository))
        let callsBefore = await service.capturedCalls().count
        store.startProject(conflicted)
        try await Task.sleep(for: .milliseconds(30))
        XCTAssertTrue(store.actionResults.isEmpty)
        let callsAfter = await service.capturedCalls().count
        XCTAssertEqual(
            callsAfter,
            callsBefore,
            "a repository membership conflict must fail before any coordinator command"
        )
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

        let preview = try XCTUnwrap(backup.manifestRecord())
        XCTAssertEqual(preview.checksum, .unknown, "inventory preview must not claim an unread artifact is current")
        XCTAssertEqual(preview.restoreTest, .passed, "manifest restore-test evidence should remain visible")
        XCTAssertFalse(preview.isStronglyVerified, "manifest parsing alone must not enable restore")

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

        let locator = PortableSkillLocator(
            environment: ["DEVCOORDINATOR_ROOT": root.path],
            currentDirectory: "/unused",
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { nil })
        )
        XCTAssertEqual(try locator.scriptPath(for: .coordinator), script.path)
    }

    func testAutomaticPathsUseAccountHomeWhenFoundationHomesAreRemapped() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let accountHome = root.appendingPathComponent("account-home", isDirectory: true)
        let remappedHome = root.appendingPathComponent("remapped-foundation-home", isDirectory: true)
        let accountCoordinator = accountHome.appendingPathComponent(".codex/agent-coordinator", isDirectory: true)
        let remappedCoordinator = remappedHome.appendingPathComponent(".codex/agent-coordinator", isDirectory: true)
        let accountHelper = accountHome.appendingPathComponent(".codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py")
        let remappedHelper = remappedHome.appendingPathComponent(".codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py")
        for coordinator in [accountCoordinator, remappedCoordinator] {
            try FileManager.default.createDirectory(at: coordinator, withIntermediateDirectories: true)
            try Data(#"{"version":2}"#.utf8).write(to: coordinator.appendingPathComponent("state.json"))
        }
        for helper in [accountHelper, remappedHelper] {
            try FileManager.default.createDirectory(at: helper.deletingLastPathComponent(), withIntermediateDirectories: true)
            XCTAssertTrue(FileManager.default.createFile(atPath: helper.path, contents: Data("#!/usr/bin/env python3\n".utf8)))
        }

        let remappedEnvironment = [
            "HOME": remappedHome.path,
            "CFFIXED_USER_HOME": remappedHome.path,
        ]
        let resolver = POSIXAccountHomeResolver(resolveAccountHome: { accountHome.path })
        let origins = FileSystemCoordinatorOriginDiscovery(
            environment: remappedEnvironment,
            accountHomeResolver: resolver
        ).origins()
        XCTAssertEqual(origins.map(\.home), [accountCoordinator.path])
        XCTAssertFalse(origins.contains { $0.home == remappedCoordinator.path })

        let locator = PortableSkillLocator(
            environment: remappedEnvironment,
            currentDirectory: root.appendingPathComponent("unrelated-checkout").path,
            bundleResourceRoot: nil,
            accountHomeResolver: resolver
        )
        XCTAssertEqual(try locator.scriptPath(for: .coordinator), accountHelper.path)
        XCTAssertNotEqual(try locator.scriptPath(for: .coordinator), remappedHelper.path)

        let configurationStore = PrivateCoordinatorConfigurationStore(accountHomeResolver: resolver)
        XCTAssertEqual(
            configurationStore.configurationURL.path,
            accountHome.appendingPathComponent("Library/Application Support/CodexOpsConsole/coordinator-configuration.json").path
        )
    }

    func testAutomaticDiscoveryAggregatesTwoParallInstancesForOneAccount() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let accountHome = root.appendingPathComponent("account-home", isDirectory: true)
        let accountCoordinator = accountHome.appendingPathComponent(".codex/agent-coordinator", isDirectory: true)
        let firstInstance = accountHome.appendingPathComponent(
            "Library/Application Support/Parall/ChatGPT Alpha/.codex/agent-coordinator",
            isDirectory: true
        )
        let secondInstance = accountHome.appendingPathComponent(
            "Library/Application Support/Parall/Codex Beta/.codex/agent-coordinator",
            isDirectory: true
        )
        for coordinator in [accountCoordinator, firstInstance, secondInstance] {
            try FileManager.default.createDirectory(at: coordinator, withIntermediateDirectories: true)
            try Data(#"{"version":2}"#.utf8).write(to: coordinator.appendingPathComponent("state.json"))
        }

        let origins = FileSystemCoordinatorOriginDiscovery(
            environment: [
                "HOME": firstInstance.deletingLastPathComponent().deletingLastPathComponent().path,
                "CFFIXED_USER_HOME": firstInstance.deletingLastPathComponent().deletingLastPathComponent().path,
            ],
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { accountHome.path })
        ).origins()

        XCTAssertEqual(
            origins.map(\.home),
            [accountCoordinator.path, firstInstance.path, secondInstance.path],
            "one Board must aggregate the login-account coordinator and both discoverable Parall instance homes"
        )
        XCTAssertEqual(Set(origins.map(\.id)).count, 3)
    }

    func testAutomaticDiscoveryDeduplicatesExplicitAliasAndAutomaticRealSource() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let accountHome = root.appendingPathComponent("account-home", isDirectory: true)
        let coordinator = accountHome.appendingPathComponent(".codex/agent-coordinator", isDirectory: true)
        let alias = root.appendingPathComponent("configured-coordinator-alias", isDirectory: true)
        try FileManager.default.createDirectory(at: coordinator, withIntermediateDirectories: true)
        try Data(#"{"version":2}"#.utf8).write(to: coordinator.appendingPathComponent("state.json"))
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: coordinator)

        let origins = FileSystemCoordinatorOriginDiscovery(
            environment: ["CODEX_AGENT_COORDINATOR_HOME": alias.path],
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { accountHome.path })
        ).origins()

        XCTAssertEqual(origins.count, 1)
        XCTAssertEqual(origins.first?.label, "Configured", "the explicit candidate keeps precedence after physical deduplication")
        XCTAssertEqual(origins.first?.home, coordinator.resolvingSymlinksInPath().path)
        XCTAssertEqual(origins.first?.id, coordinator.resolvingSymlinksInPath().path)
    }

    func testExplicitCoordinatorHomeAndConfigurationURLKeepPrecedence() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let pseudoRuntimeHome = root.appendingPathComponent("pseudo-runtime-home", isDirectory: true)
        let configuredCoordinator = pseudoRuntimeHome.appendingPathComponent(".codex/agent-coordinator", isDirectory: true)
        try FileManager.default.createDirectory(at: configuredCoordinator, withIntermediateDirectories: true)
        let invalidResolver = POSIXAccountHomeResolver(resolveAccountHome: { "relative-account-home" })

        let origins = FileSystemCoordinatorOriginDiscovery(
            environment: [
                "HOME": pseudoRuntimeHome.path,
                "CFFIXED_USER_HOME": pseudoRuntimeHome.path,
                "CODEX_AGENT_COORDINATOR_HOME": configuredCoordinator.path,
            ],
            accountHomeResolver: invalidResolver
        ).origins()
        XCTAssertEqual(origins.first?.label, "Configured")
        XCTAssertEqual(origins.first?.home, configuredCoordinator.path)
        XCTAssertEqual(origins.count, 1)

        let explicitConfiguration = root.appendingPathComponent("explicit/configuration.json")
        let configurationStore = PrivateCoordinatorConfigurationStore(
            configurationURL: explicitConfiguration,
            accountHomeResolver: invalidResolver
        )
        XCTAssertEqual(configurationStore.configurationURL, explicitConfiguration)
        XCTAssertEqual(
            configurationStore.lastKnownGoodURL,
            explicitConfiguration.deletingPathExtension().appendingPathExtension("last-known-good.json")
        )
    }

    func testInvalidAccountHomeFailsClosedWithoutUsingHostileRuntimeHome() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let hostileHome = root.appendingPathComponent("hostile-runtime-home", isDirectory: true)
        let hostileCoordinator = hostileHome.appendingPathComponent(".codex/agent-coordinator", isDirectory: true)
        let hostileHelper = hostileHome.appendingPathComponent(".codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py")
        try FileManager.default.createDirectory(at: hostileCoordinator, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: hostileHelper.deletingLastPathComponent(), withIntermediateDirectories: true)
        XCTAssertTrue(FileManager.default.createFile(atPath: hostileHelper.path, contents: Data()))
        let hostileEnvironment = [
            "HOME": hostileHome.path,
            "CFFIXED_USER_HOME": hostileHome.path,
        ]

        for resolver in [
            POSIXAccountHomeResolver(resolveAccountHome: { nil }),
            POSIXAccountHomeResolver(resolveAccountHome: { "relative-account-home" }),
        ] {
            XCTAssertTrue(
                FileSystemCoordinatorOriginDiscovery(
                    environment: hostileEnvironment,
                    accountHomeResolver: resolver
                ).origins().isEmpty
            )
            XCTAssertThrowsError(
                try PortableSkillLocator(
                    environment: hostileEnvironment,
                    currentDirectory: root.appendingPathComponent("unrelated").path,
                    bundleResourceRoot: nil,
                    accountHomeResolver: resolver
                ).scriptPath(for: .coordinator)
            )

            let configurationStore = PrivateCoordinatorConfigurationStore(accountHomeResolver: resolver)
            XCTAssertNotEqual(
                configurationStore.configurationURL.path,
                hostileHome.appendingPathComponent("Library/Application Support/CodexOpsConsole/coordinator-configuration.json").path
            )
            let load = configurationStore.load()
            XCTAssertNil(load.configuration)
            XCTAssertTrue(load.warning?.contains("effective POSIX account home could not be resolved") == true)
            XCTAssertThrowsError(try configurationStore.save(CoordinatorConfiguration()))
        }
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: hostileHome.appendingPathComponent("Library/Application Support/CodexOpsConsole/coordinator-configuration.json").path
            )
        )
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
            currentDirectory: checkout.path,
            bundleResourceRoot: bundleRoot.path,
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { home.path })
        )
        XCTAssertEqual(try packaged.scriptPath(for: .coordinator), bundled.path)

        let explicitlyOverridden = PortableSkillLocator(
            environment: ["DEVCOORDINATOR_ROOT": override.path],
            currentDirectory: checkout.path,
            bundleResourceRoot: bundleRoot.path,
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { home.path })
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

    func testOrdinaryCoordinatorOutputOverOneMiBRemainsTruncated() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let script = root.appendingPathComponent("large-output.py")
        try Data("import sys\nsys.stdout.write('x' * 1_100_000)\n".utf8).write(to: script)
        let executor = SystemCommandExecutor(
            temporaryRoot: root.appendingPathComponent("spools"),
            baseEnvironment: ["PATH": "/usr/bin:/bin"]
        )
        let service = PythonCoordinatorService(executor: executor, scriptPath: script.path)

        let result = try await service.execute(origin: codex, arguments: ["server", "status"])

        XCTAssertTrue(result.outputTruncated)
        XCTAssertNotEqual(result.exitStatus, 0)
        XCTAssertLessThanOrEqual(result.stdout.utf8.count + result.stderr.utf8.count, 1_048_576)
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

    func testDefaultConfigurationMigratesRemappedLegacySettingsWithoutLosingDisabledSourcesOrRefreshPolicy() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let accountHome = root.appendingPathComponent("account-home", isDirectory: true)
        let legacyConfigurationURL = root
            .appendingPathComponent("remapped-foundation-app-support/CodexOpsConsole", isDirectory: true)
            .appendingPathComponent("coordinator-configuration.json")
        let legacyStore = PrivateCoordinatorConfigurationStore(configurationURL: legacyConfigurationURL)
        let legacyConfiguration = CoordinatorConfiguration(
            sources: [
                .init(label: "Enabled", home: "/tmp/enabled-coordinator", enabled: true),
                .init(label: "Intentionally disabled", home: "/tmp/disabled-coordinator", enabled: false),
            ],
            refreshPolicy: .interval(seconds: 75)
        )
        try legacyStore.save(legacyConfiguration)
        let legacyPrimaryBeforeMigration = try Data(contentsOf: legacyConfigurationURL)
        let legacyBackupBeforeMigration = try Data(contentsOf: legacyStore.lastKnownGoodURL)

        let migratedStore = PrivateCoordinatorConfigurationStore(
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { accountHome.path }),
            legacyConfigurationURL: legacyConfigurationURL
        )
        let result = migratedStore.load()

        XCTAssertEqual(result.configuration, try legacyConfiguration.validated())
        XCTAssertFalse(result.usedLastKnownGood)
        XCTAssertEqual(result.configuration?.sources.first(where: { $0.label == "Intentionally disabled" })?.enabled, false)
        XCTAssertEqual(result.configuration?.refreshPolicy, .interval(seconds: 75))
        XCTAssertEqual(
            migratedStore.configurationURL.path,
            accountHome.appendingPathComponent("Library/Application Support/CodexOpsConsole/coordinator-configuration.json").path
        )
        XCTAssertEqual(PrivateCoordinatorConfigurationStore(configurationURL: migratedStore.configurationURL).load().configuration, try legacyConfiguration.validated())
        XCTAssertTrue(FileManager.default.fileExists(atPath: migratedStore.lastKnownGoodURL.path))
        XCTAssertEqual(try Data(contentsOf: legacyConfigurationURL), legacyPrimaryBeforeMigration)
        XCTAssertEqual(try Data(contentsOf: legacyStore.lastKnownGoodURL), legacyBackupBeforeMigration)
    }

    func testDefaultConfigurationMigratesLegacyLastKnownGoodWhenLegacyPrimaryIsCorrupt() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let accountHome = root.appendingPathComponent("account-home", isDirectory: true)
        let legacyConfigurationURL = root
            .appendingPathComponent("remapped-foundation-app-support/CodexOpsConsole", isDirectory: true)
            .appendingPathComponent("coordinator-configuration.json")
        let legacyStore = PrivateCoordinatorConfigurationStore(configurationURL: legacyConfigurationURL)
        let recoverableConfiguration = CoordinatorConfiguration(
            sources: [.init(label: "Disabled lab", home: "/tmp/disabled-lab", enabled: false)],
            refreshPolicy: .manual()
        )
        try legacyStore.save(recoverableConfiguration)
        try Data("corrupt legacy primary".utf8).write(to: legacyConfigurationURL)
        let legacyBackupBeforeMigration = try Data(contentsOf: legacyStore.lastKnownGoodURL)

        let migratedStore = PrivateCoordinatorConfigurationStore(
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { accountHome.path }),
            legacyConfigurationURL: legacyConfigurationURL
        )
        let result = migratedStore.load()

        XCTAssertEqual(result.configuration, try recoverableConfiguration.validated())
        XCTAssertTrue(result.usedLastKnownGood)
        XCTAssertNotNil(result.warning)
        XCTAssertEqual(PrivateCoordinatorConfigurationStore(configurationURL: migratedStore.configurationURL).load().configuration, try recoverableConfiguration.validated())
        XCTAssertEqual(try Data(contentsOf: legacyConfigurationURL), Data("corrupt legacy primary".utf8))
        XCTAssertEqual(try Data(contentsOf: legacyStore.lastKnownGoodURL), legacyBackupBeforeMigration)
    }

    func testDefaultConfigurationAlreadyAtAccountPathWinsOverRemappedLegacySettings() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let accountHome = root.appendingPathComponent("account-home", isDirectory: true)
        let accountConfigurationURL = accountHome
            .appendingPathComponent("Library/Application Support/CodexOpsConsole", isDirectory: true)
            .appendingPathComponent("coordinator-configuration.json")
        let legacyConfigurationURL = root
            .appendingPathComponent("remapped-foundation-app-support/CodexOpsConsole", isDirectory: true)
            .appendingPathComponent("coordinator-configuration.json")
        let accountConfiguration = CoordinatorConfiguration(
            sources: [.init(label: "Account source", home: "/tmp/account-source", enabled: true)],
            refreshPolicy: .interval(seconds: 15)
        )
        let staleLegacyConfiguration = CoordinatorConfiguration(
            sources: [.init(label: "Stale disabled source", home: "/tmp/stale-source", enabled: false)],
            refreshPolicy: .manual()
        )
        try PrivateCoordinatorConfigurationStore(configurationURL: accountConfigurationURL).save(accountConfiguration)
        try PrivateCoordinatorConfigurationStore(configurationURL: legacyConfigurationURL).save(staleLegacyConfiguration)

        let store = PrivateCoordinatorConfigurationStore(
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { accountHome.path }),
            legacyConfigurationURL: legacyConfigurationURL
        )

        XCTAssertEqual(store.load().configuration, try accountConfiguration.validated())
        XCTAssertNotEqual(store.load().configuration, try staleLegacyConfiguration.validated())
    }

    func testExplicitConfigurationURLDoesNotConsultOrMigrateRemappedLegacySettings() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let explicitConfigurationURL = root.appendingPathComponent("explicit/configuration.json")
        let legacyConfigurationURL = root
            .appendingPathComponent("remapped-foundation-app-support/CodexOpsConsole", isDirectory: true)
            .appendingPathComponent("coordinator-configuration.json")
        let legacyConfiguration = CoordinatorConfiguration(
            sources: [.init(label: "Legacy", home: "/tmp/legacy-source", enabled: false)],
            refreshPolicy: .manual()
        )
        try PrivateCoordinatorConfigurationStore(configurationURL: legacyConfigurationURL).save(legacyConfiguration)

        let explicitStore = PrivateCoordinatorConfigurationStore(
            configurationURL: explicitConfigurationURL,
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { nil }),
            legacyConfigurationURL: legacyConfigurationURL
        )

        XCTAssertNil(explicitStore.load().configuration)
        XCTAssertFalse(FileManager.default.fileExists(atPath: explicitConfigurationURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: explicitStore.lastKnownGoodURL.path))
    }

    func testConfigurationSaveRollsBackTheWholePairWhenAReplacementDoesNotComplete() throws {
        enum InjectedFailure: Error { case afterLastKnownGood }

        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let configurationURL = root.appendingPathComponent("configuration.json")
        let original = CoordinatorConfiguration(
            sources: [.init(label: "Original", home: "/tmp/original")],
            refreshPolicy: .interval(seconds: 10)
        )
        let replacement = CoordinatorConfiguration(
            sources: [.init(label: "Replacement", home: "/tmp/replacement")],
            refreshPolicy: .interval(seconds: 20)
        )
        let originalStore = PrivateCoordinatorConfigurationStore(configurationURL: configurationURL)
        try originalStore.save(original)
        let originalPrimary = try Data(contentsOf: originalStore.configurationURL)
        let originalLastKnownGood = try Data(contentsOf: originalStore.lastKnownGoodURL)

        let interruptedStore = PrivateCoordinatorConfigurationStore(
            configurationURL: configurationURL,
            transactionObserver: { event in
                if case .replacedLastKnownGood = event {
                    throw InjectedFailure.afterLastKnownGood
                }
            }
        )
        XCTAssertThrowsError(try interruptedStore.save(replacement))

        XCTAssertEqual(try Data(contentsOf: originalStore.configurationURL), originalPrimary)
        XCTAssertEqual(try Data(contentsOf: originalStore.lastKnownGoodURL), originalLastKnownGood)
        XCTAssertEqual(originalStore.load().configuration, try original.validated())
    }

    func testTwoConfigurationWriterProcessesSerializeThePairWithLockOrderLastWriterWins() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let configurationURL = root.appendingPathComponent("configuration.json")
        let first = CoordinatorConfiguration(
            sources: [.init(label: "First", home: "/tmp/first")],
            refreshPolicy: .interval(seconds: 11)
        )
        let second = CoordinatorConfiguration(
            sources: [.init(label: "Second", home: "/tmp/second", enabled: false)],
            refreshPolicy: .manual()
        )

        let firstEvents = root.appendingPathComponent("first-events", isDirectory: true)
        let secondEvents = root.appendingPathComponent("second-events", isDirectory: true)
        try FileManager.default.createDirectory(at: firstEvents, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: secondEvents, withIntermediateDirectories: true)

        let firstProcess = try launchConfigurationWriterFixture(
            configurationURL: configurationURL,
            configuration: first,
            eventDirectory: firstEvents
        )
        defer { if firstProcess.process.isRunning { firstProcess.process.terminate() } }
        try waitForFile(firstEvents.appendingPathComponent("waiting"))
        try waitForFile(firstEvents.appendingPathComponent("acquired"))

        let secondProcess = try launchConfigurationWriterFixture(
            configurationURL: configurationURL,
            configuration: second,
            eventDirectory: secondEvents
        )
        defer { if secondProcess.process.isRunning { secondProcess.process.terminate() } }
        try waitForFile(secondEvents.appendingPathComponent("waiting"))
        Thread.sleep(forTimeInterval: 0.2)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: secondEvents.appendingPathComponent("acquired").path),
            "the second process must remain outside the save transaction while the first process owns the lock"
        )

        XCTAssertTrue(FileManager.default.createFile(atPath: firstEvents.appendingPathComponent("release").path, contents: Data()))
        try waitForConfigurationWriter(firstProcess)
        try waitForFile(secondEvents.appendingPathComponent("acquired"))
        XCTAssertTrue(FileManager.default.createFile(atPath: secondEvents.appendingPathComponent("release").path, contents: Data()))
        try waitForConfigurationWriter(secondProcess)

        let primary = try JSONDecoder().decode(CoordinatorConfiguration.self, from: Data(contentsOf: configurationURL))
        let lastKnownGoodURL = configurationURL.deletingPathExtension().appendingPathExtension("last-known-good.json")
        let lastKnownGood = try JSONDecoder().decode(CoordinatorConfiguration.self, from: Data(contentsOf: lastKnownGoodURL))
        XCTAssertEqual(primary, try second.validated())
        XCTAssertEqual(lastKnownGood, try second.validated())
        XCTAssertEqual(primary, lastKnownGood, "a completed process save must never leave files from different writers")
    }

    func testConfigurationWriterProcessFixture() throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["DEVOPS_BOARD_CONFIGURATION_WRITER_FIXTURE"] == "1" else { return }
        guard let configurationPath = environment["DEVOPS_BOARD_CONFIGURATION_WRITER_PATH"],
              let sourceLabel = environment["DEVOPS_BOARD_CONFIGURATION_WRITER_LABEL"],
              let sourceHome = environment["DEVOPS_BOARD_CONFIGURATION_WRITER_HOME"],
              let enabledValue = environment["DEVOPS_BOARD_CONFIGURATION_WRITER_ENABLED"],
              let refreshMode = environment["DEVOPS_BOARD_CONFIGURATION_WRITER_REFRESH_MODE"],
              let eventDirectoryPath = environment["DEVOPS_BOARD_CONFIGURATION_WRITER_EVENTS"]
        else { throw ConfigurationWriterFixtureFailure(description: "configuration writer fixture environment is incomplete") }

        let refreshPolicy: CoordinatorRefreshPolicy
        if refreshMode == CoordinatorRefreshMode.manual.rawValue {
            refreshPolicy = .manual()
        } else {
            guard let intervalValue = environment["DEVOPS_BOARD_CONFIGURATION_WRITER_REFRESH_INTERVAL"],
                  let interval = Double(intervalValue)
            else { throw ConfigurationWriterFixtureFailure(description: "configuration writer fixture interval is invalid") }
            refreshPolicy = .interval(seconds: interval)
        }
        let eventDirectory = URL(fileURLWithPath: eventDirectoryPath, isDirectory: true)
        let releaseURL = eventDirectory.appendingPathComponent("release")
        let store = PrivateCoordinatorConfigurationStore(
            configurationURL: URL(fileURLWithPath: configurationPath),
            transactionObserver: { event in
                switch event {
                case .waitingForExclusiveLock:
                    try createFixtureMarker(eventDirectory.appendingPathComponent("waiting"))
                case .acquiredExclusiveLock:
                    try createFixtureMarker(eventDirectory.appendingPathComponent("acquired"))
                    try waitForFile(releaseURL, timeout: 10)
                case .replacedLastKnownGood, .replacedPrimary:
                    break
                }
            }
        )
        try store.save(
            CoordinatorConfiguration(
                sources: [.init(label: sourceLabel, home: sourceHome, enabled: enabledValue == "1")],
                refreshPolicy: refreshPolicy
            )
        )
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

    func testCoordinatorConfigurationRejectsTwoAliasesOfOnePhysicalSource() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let coordinator = root.appendingPathComponent("physical-coordinator", isDirectory: true)
        let alias = root.appendingPathComponent("coordinator-alias", isDirectory: true)
        try FileManager.default.createDirectory(at: coordinator, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: coordinator)

        let duplicate = CoordinatorConfiguration(sources: [
            .init(label: "Physical", home: coordinator.path),
            .init(label: "Alias", home: alias.path),
        ])

        XCTAssertThrowsError(try duplicate.validated()) { error in
            XCTAssertEqual(
                error as? CoordinatorConfigurationError,
                .duplicateSource(coordinator.resolvingSymlinksInPath().path)
            )
        }

        let futurePhysicalParent = root.appendingPathComponent("future-physical-parent", isDirectory: true)
        let futureAliasParent = root.appendingPathComponent("future-alias-parent", isDirectory: true)
        try FileManager.default.createDirectory(at: futurePhysicalParent, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: futureAliasParent, withDestinationURL: futurePhysicalParent)
        let nonexistentAlias = futureAliasParent.appendingPathComponent("not-created/agent-coordinator")
        let resolvedPhysicalParent = try XCTUnwrap(futurePhysicalParent.path.withCString { realpath($0, nil) })
        defer { free(resolvedPhysicalParent) }
        let nonexistentPhysical = URL(fileURLWithPath: String(cString: resolvedPhysicalParent), isDirectory: true)
            .appendingPathComponent("not-created/agent-coordinator")
        let validated = try CoordinatorSourceConfiguration(label: "Future", home: nonexistentAlias.path).validated()
        XCTAssertFalse(FileManager.default.fileExists(atPath: nonexistentAlias.path))
        XCTAssertEqual(validated.home, nonexistentPhysical.standardizedFileURL.path)
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
    func testDisabledConfiguredAliasSuppressesTheSamePhysicalAutomaticSource() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let coordinator = root.appendingPathComponent("physical-coordinator", isDirectory: true)
        let alias = root.appendingPathComponent("disabled-coordinator-alias", isDirectory: true)
        try FileManager.default.createDirectory(at: coordinator, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: coordinator)

        let automatic = CoordinatorOrigin(label: "Automatic", home: coordinator.path)
        let configuration = CoordinatorConfiguration(
            sources: [.init(label: "Disabled alias", home: alias.path, enabled: false)],
            refreshPolicy: .manual()
        )
        let service = OriginSequencedCoordinatorService(results: [
            automatic.id: [.success(inventoryExecution(home: automatic.home, serverName: "must-not-load"))],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [automatic]),
            configurationStore: StaticConfigurationStore(configuration: configuration)
        )

        await store.loadInventory()

        let calls = await service.capturedCalls()
        XCTAssertTrue(calls.isEmpty)
        XCTAssertTrue(store.sourceStates.isEmpty)
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
    func testAutomaticRefreshWaitsForAFullIdleIntervalAfterSlowInventoryCompletes() async throws {
        XCTAssertEqual(CoordinatorRefreshPolicy.default.intervalSeconds, 30)
        let service = DelayedCountingCoordinatorService(
            result: inventoryExecution(home: codex.home, serverName: "web"),
            delay: .milliseconds(900)
        )
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .interval(seconds: 1))
            )
        )

        store.setSurfaceVisible(.window, true)
        defer { store.setSurfaceVisible(.window, false) }
        try await Task.sleep(for: .milliseconds(2_250))

        let callCount = await service.callCount()
        XCTAssertEqual(
            callCount,
            2,
            "a slow automatic refresh must finish before the next full idle interval begins"
        )
    }

    @MainActor
    func testVisibilitySchedulingOnlyRefreshesOnAggregateHiddenToVisibleEdges() async throws {
        let clock = MutableTestClock(Date(timeIntervalSince1970: 1_000))
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(inventoryExecution(home: codex.home, serverName: "first")),
                .success(inventoryExecution(home: codex.home, serverName: "second")),
            ]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .interval(seconds: 3_600))
            ),
            clock: clock
        )

        store.setSurfaceVisible(.popover, true)
        try await waitUntilAsync {
            let count = await service.capturedCalls().count
            return count == 1 && !store.isLoading
        }
        clock.advance(by: 3_601)

        store.setSurfaceVisible(.popover, true)
        store.setSurfaceVisible(.window, true)
        store.setSurfaceVisible(.popover, false)
        try await Task.sleep(for: .milliseconds(50))
        let callsAfterHandoff = await service.capturedCalls()
        XCTAssertEqual(
            callsAfterHandoff.count,
            1,
            "duplicate callbacks and visible-surface handoff must not restart inventory"
        )

        store.setSurfaceVisible(.window, false)
        store.setSurfaceVisible(.popover, true)
        try await waitUntilAsync {
            let count = await service.capturedCalls().count
            return count == 2 && !store.isLoading
        }
        XCTAssertEqual(store.inventory.servers.first?.name, "second")
        store.setSurfaceVisible(.popover, false)
    }

    @MainActor
    func testBackgroundRefreshRetainsLoadedPresentationUntilReplacementArrives() async throws {
        let clock = MutableTestClock(Date(timeIntervalSince1970: 2_000))
        let service = GatedSequencedCoordinatorService(results: [
            inventoryExecution(home: codex.home, serverName: "first"),
            inventoryExecution(home: codex.home, serverName: "second"),
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .interval(seconds: 30))
            ),
            clock: clock
        )

        let initialLoad = Task { await store.loadInventory() }
        try await waitUntilAsync { await service.startedCallCount() == 1 }
        XCTAssertTrue(store.isLoading)
        XCTAssertTrue(store.isInitialInventoryLoading)
        XCTAssertEqual(store.sourceStates.first?.phase, .loading)
        XCTAssertTrue(store.capabilityStates.allSatisfy { $0.phase == .loading })
        await service.release(call: 1)
        await initialLoad.value
        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertEqual(store.presentationSnapshot.level, .nominal)

        clock.advance(by: 31)
        let backgroundLoad = Task { await store.loadInventory() }
        try await waitUntilAsync { await service.startedCallCount() == 2 }
        XCTAssertTrue(store.isLoading)
        XCTAssertFalse(store.isInitialInventoryLoading)
        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertTrue(store.capabilityStates.allSatisfy { $0.phase == .available })
        XCTAssertEqual(store.inventory.servers.first?.name, "first")
        XCTAssertEqual(store.presentationSnapshot.level, .nominal)
        await service.release(call: 2)
        await backgroundLoad.value

        XCTAssertFalse(store.isLoading)
        XCTAssertEqual(store.inventory.servers.first?.name, "second")
        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
    }

    @MainActor
    func testRetryAfterInitialFailureShowsLoadingUntilFirstSnapshotArrives() async throws {
        let service = GatedSequencedCoordinatorService(outcomes: [
            .failure(.offline),
            .success(inventoryExecution(home: codex.home, serverName: "recovered")),
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        let failedLoad = Task { await store.loadInventory(force: true) }
        try await waitUntilAsync { await service.startedCallCount() == 1 }
        await service.release(call: 1)
        await failedLoad.value
        XCTAssertEqual(store.sourceStates.first?.phase, .failed)
        XCTAssertTrue(store.inventory.servers.isEmpty)

        let retry = Task { await store.loadInventory(force: true) }
        try await waitUntilAsync { await service.startedCallCount() == 2 }
        XCTAssertTrue(store.isLoading)
        XCTAssertTrue(store.isInitialInventoryLoading)
        XCTAssertEqual(store.sourceStates.first?.phase, .loading)
        XCTAssertTrue(store.capabilityStates.allSatisfy { $0.phase == .loading })
        await service.release(call: 2)
        await retry.value

        XCTAssertFalse(store.isLoading)
        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertEqual(store.inventory.servers.first?.name, "recovered")
    }

    @MainActor
    func testRealisticLargeInventoryTraversesProductionExecutorAndLoadsStore() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let origin = CoordinatorOrigin(label: "Large fixture", home: root.appendingPathComponent("coordinator-home").path)
        let payload = try realisticAccumulatedInventoryPayload(home: origin.home)
        let decodedFixture = try JSONDecoder().decode(Inventory.self, from: payload)
        let historySamples = decodedFixture.docker.containers.reduce(0) { partial, container in
            partial + (container.statsHistory?.count ?? 0)
        }
        XCTAssertGreaterThan(payload.count, 1_048_576, "the recall fixture must cross the former production limit")
        XCTAssertEqual(decodedFixture.docker.containers.count, 15)
        XCTAssertEqual(decodedFixture.postgres.count, 9)
        XCTAssertEqual(historySamples, 548)
        try payload.write(to: root.appendingPathComponent("inventory.json"))
        let enrichment = try JSONSerialization.data(
            withJSONObject: inventoryJSONObject(home: origin.home, containers: [], postgres: []),
            options: [.sortedKeys]
        )
        try enrichment.write(to: root.appendingPathComponent("enrichment.json"))
        let script = root.appendingPathComponent("coordinator.py")
        let scriptText = #"""
        from pathlib import Path
        import sys

        args = sys.argv[1:]
        try:
            history_index = args.index("--stats-history-limit")
            has_history_limit = args[history_index + 1] == "30"
        except (ValueError, IndexError):
            has_history_limit = False
        if not args or args[0] != "inventory" or "--compact-json" not in args or not has_history_limit:
            print("inventory transport flags are missing", file=sys.stderr)
            raise SystemExit(64)
        fixture = "enrichment.json" if "--no-docker" in args else "inventory.json"
        sys.stdout.buffer.write(Path(__file__).with_name(fixture).read_bytes())
        """#
        try Data(scriptText.utf8).write(to: script)

        let executor = SystemCommandExecutor(
            temporaryRoot: root.appendingPathComponent("spools"),
            baseEnvironment: ["PATH": "/usr/bin:/bin"]
        )
        let service = PythonCoordinatorService(executor: executor, scriptPath: script.path)
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [origin]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        await store.loadInventory(force: true)

        XCTAssertFalse(store.isLoading)
        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertEqual(store.inventory.docker.containers.count, 15)
        XCTAssertEqual(
            store.inventory.docker.containers.reduce(0) { $0 + ($1.statsHistory?.count ?? 0) },
            548
        )
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .docker }?.phase,
            .available
        )
        XCTAssertNil(store.inventoryIssue)
        XCTAssertEqual(store.presentationSnapshot.level, .nominal)
    }

    @MainActor
    func testTruncatedInventoryReportsConciseLimitFailureWithoutClaimingDockerIsUnavailable() async throws {
        let partialMarker = "partial-inventory-json-must-not-reach-the-ui"
        let truncated = CommandExecution(
            stdout: String(repeating: partialMarker, count: 30_000),
            stderr: "",
            exitStatus: -1,
            outputTruncated: true
        )
        let service = OriginSequencedCoordinatorService(results: [codex.id: [.success(truncated)]])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        await store.loadInventory(force: true)

        let sourceError = try XCTUnwrap(store.sourceStates.first?.error)
        let issueDetails = try XCTUnwrap(store.inventoryIssue?.details)
        XCTAssertEqual(store.sourceStates.first?.phase, .failed)
        XCTAssertTrue(sourceError.localizedCaseInsensitiveContains("output limit"))
        XCTAssertLessThan(sourceError.utf8.count, 512)
        XCTAssertLessThan(issueDetails.utf8.count, 2_048)
        XCTAssertFalse(sourceError.contains(partialMarker))
        XCTAssertFalse(issueDetails.contains(partialMarker))
        XCTAssertTrue(
            store.explicitlyUnavailableDockerCapabilities.isEmpty,
            "a failed coordinator makes Docker unknown; it is not evidence that Docker itself is unavailable"
        )
    }

    @MainActor
    func testBackupEnrichmentSkipsDuplicateDockerObservationAndMergesOnlyBackups() async throws {
        let initialJSON = """
        {"coordinator_home":"\(codex.home)","state_path":"\(codex.home)/state.json","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"containers":[{"id":"cid","name":"db","project":"/repo","status":"Up","stats":{"cpu_percent":17.5}}],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}
        """
        let enrichmentJSON = """
        {"coordinator_home":"\(codex.home)","state_path":"\(codex.home)/state.json","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"available":null,"containers":[],"postgres":[]},"postgres":[],"backups":[{"path":"/repo/.codex-db-backups/app.dump","size":42}],"project_usage":[]}
        """
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(.init(stdout: initialJSON, stderr: "", exitStatus: 0)),
                .success(.init(stdout: enrichmentJSON, stderr: "", exitStatus: 0)),
            ]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        await store.loadInventory()

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.map(\.1), [
            ["inventory", "--compact-json", "--stats-history-limit", "30"],
            ["inventory", "--compact-json", "--stats-history-limit", "30", "--no-docker", "--backup-dir", "/repo/.codex-db-backups"],
        ])
        XCTAssertEqual(store.inventory.docker.containers.first?.name, "db")
        XCTAssertEqual(store.inventory.docker.containers.first?.stats?.cpuPercent, 17.5)
        XCTAssertEqual(store.inventory.backups.first?.path, "/repo/.codex-db-backups/app.dump")
    }

    @MainActor
    func testFailedBackupEnrichmentRetainsRuntimeSnapshotAndDegradesOnlyDatabaseCapability() async throws {
        let initialJSON = """
        {"coordinator_home":"\(codex.home)","state_path":"\(codex.home)/state.json","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"containers":[{"id":"cid","name":"db","project":"/repo","status":"Up","stats":{"cpu_percent":8.25}}],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}
        """
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(.init(stdout: initialJSON, stderr: "", exitStatus: 0)),
                .failure(.offline),
            ]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        await store.loadInventory()

        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertEqual(store.inventory.docker.containers.first?.name, "db")
        XCTAssertEqual(store.inventory.docker.containers.first?.stats?.cpuPercent, 8.25)
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .docker }?.phase,
            .available
        )
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .database }?.phase,
            .unavailable
        )
        XCTAssertTrue(store.inventoryIssue?.details.localizedCaseInsensitiveContains("backup inventory incomplete") == true)
    }

    @MainActor
    func testDockerAndBackupEnrichmentFailuresAreBothRetainedInDiagnostics() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [
                .success(inventoryWithDockerUnavailableExecution(home: codex.home)),
                .failure(.offline),
            ]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        await store.loadInventory()

        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .docker }?.phase,
            .unavailable
        )
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .database }?.phase,
            .unavailable
        )
        let details = store.inventoryIssue?.details ?? ""
        XCTAssertTrue(details.localizedCaseInsensitiveContains("backup inventory incomplete"))
        XCTAssertTrue(details.localizedCaseInsensitiveContains("docker daemon unavailable"))
    }

    @MainActor
    func testInventoryRefreshDoesNotHashMultiGigabyteBackupArtifactsEagerly() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let artifact = directory.appendingPathComponent("large.dump")
        let manifest = URL(fileURLWithPath: artifact.path + ".manifest.json")
        XCTAssertTrue(FileManager.default.createFile(atPath: artifact.path, contents: Data()))
        let handle = try FileHandle(forWritingTo: artifact)
        try handle.truncate(atOffset: 8 * 1_024 * 1_024 * 1_024)
        try handle.close()
        let manifestJSON = """
        {"schema_version":2,"created_at":"2026-07-13T12:00:00Z","scope":"database","format":"custom","sha256":"recorded-sha","source":{"container":{"name":"pg","id":"cid","image":"postgres:17"},"postgres":{"database":"app","scope":"database"}},"verification":{"verified_at":"2026-07-13T12:01:00Z","mode":"test_restore","scope":"database","sha256":"recorded-sha","ok":true}}
        """
        try Data(manifestJSON.utf8).write(to: manifest)
        let inventoryJSON = """
        {"coordinator_home":"\(codex.home)","state_path":"\(codex.home)/state.json","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"containers":[],"postgres":[]},"postgres":[],"backups":[{"path":"\(artifact.path)","size":8589934592,"manifest":"\(manifest.path)"}],"project_usage":[]}
        """
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(.init(stdout: inventoryJSON, stderr: "", exitStatus: 0))]
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        let startedAt = Date()
        await store.loadInventory()
        let elapsed = Date().timeIntervalSince(startedAt)

        XCTAssertLessThan(elapsed, 0.5, "inventory refresh must not read an 8 GiB backup artifact")
        XCTAssertEqual(store.backupRecords.first?.checksum, .unknown)
        XCTAssertEqual(store.backupRecords.first?.restoreTest, .passed)
    }

    @MainActor
    func testSelectingDatabaseVerifiesOnlyItsNewestBackupOnDemand() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let artifact = directory.appendingPathComponent("app.dump")
        let manifest = URL(fileURLWithPath: artifact.path + ".manifest.json")
        XCTAssertTrue(FileManager.default.createFile(atPath: artifact.path, contents: Data("dump".utf8)))
        let checksum = try XCTUnwrap(fileSHA256(artifact.path))
        let manifestJSON = """
        {"schema_version":2,"created_at":"2026-07-13T12:00:00Z","scope":"database","format":"custom","sha256":"\(checksum)","source":{"container":{"name":"pg","id":"cid","image":"postgres:17"},"postgres":{"database":"app","scope":"database"}},"verification":{"verified_at":"2026-07-13T12:01:00Z","mode":"test_restore","scope":"database","sha256":"\(checksum)","ok":true}}
        """
        try Data(manifestJSON.utf8).write(to: manifest)
        let inventoryJSON = """
        {"coordinator_home":"\(codex.home)","state_path":"\(codex.home)/state.json","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"containers":[],"postgres":[]},"postgres":[{"id":"cid","name":"pg","image":"postgres:17","status":"Up","project":"/repo","metadata_source":"coordinator_sidecar"}],"backups":[{"path":"\(artifact.path)","size":4,"manifest":"\(manifest.path)"}],"project_usage":[]}
        """
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(.init(stdout: inventoryJSON, stderr: "", exitStatus: 0))]
        ])
        let discovery = StaticDatabaseDiscovery(database: "app", sizeBytes: 4)
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: discovery,
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        await store.loadInventory()
        XCTAssertEqual(store.backupRecords.first?.checksum, .unknown)
        let database = try XCTUnwrap(store.inventory.postgres.first)
        store.selectDatabase(database)
        try await waitUntil { store.backupRecords.first?.checksum == .verified }

        XCTAssertFalse(store.isBackupVerificationInProgress(for: database))
        XCTAssertTrue(store.backupRecords.first?.isStronglyVerified == true)
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
        XCTAssertEqual(
            store.explicitlyUnavailableDockerCapabilities.map(\.origin.id),
            [codex.id],
            "an explicitly loaded Docker-unavailable result must retain its warning"
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
            codex.id: [.success(partialReport), .success(refreshed), .success(refreshed)]
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
        XCTAssertEqual(calls.count, 3, "the failed project command must be followed by an inventory refresh")
        XCTAssertEqual(calls[1].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
        XCTAssertEqual(calls[2].1, ["inventory", "--compact-json", "--stats-history-limit", "30", "--no-docker", "--backup-dir", "/repo/.codex-db-backups"])
    }

    @MainActor
    func testThrownProjectActionFailureStillRefreshesInventory() async throws {
        let refreshed = inventoryExecution(home: codex.home, serverName: "refreshed-after-throw", project: "/repo")
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.failure(.offline), .success(refreshed), .success(refreshed)]
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
        XCTAssertEqual(calls.count, 3)
        XCTAssertEqual(calls[1].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
        XCTAssertEqual(calls[2].1, ["inventory", "--compact-json", "--stats-history-limit", "30", "--no-docker", "--backup-dir", "/repo/.codex-db-backups"])
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
        XCTAssertEqual(store.sourceStates.first?.origin.label, "Current label")
        XCTAssertEqual(store.inventory.leases.first?.origin?.label, "Current label")
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

@MainActor
private func waitUntilAsync(
    attempts: Int = 100,
    condition: @escaping @MainActor () async -> Bool
) async throws {
    for _ in 0..<attempts {
        if await condition() { return }
        try await Task.sleep(for: .milliseconds(10))
    }
    throw RuntimeError("Timed out waiting for asynchronous state")
}

private func realisticAccumulatedInventoryPayload(home: String) throws -> Data {
    // This mirrors the production failure shape: 15 observed containers, nine
    // PostgreSQL projections, and 548 accumulated telemetry samples with the
    // per-container history cap still respected. PostgreSQL projections repeat
    // container telemetry in the coordinator schema, so this naturally crosses
    // 1 MiB without padding or an implementation-shaped synthetic blob.
    let historyCounts = [120, 120, 120, 120, 68] + Array(repeating: 0, count: 10)
    let containers: [[String: Any]] = historyCounts.enumerated().map { index, historyCount in
        let shortID = String(format: "%012llx", Int64(index + 1))
        let fullID = shortID + String(repeating: "0", count: 52)
        let name = "project-\(index)-postgres"
        let history: [[String: Any]] = (0..<historyCount).map { sampleIndex in
            dockerStatsJSONObject(
                shortID: shortID,
                fullID: fullID,
                name: name,
                sampleIndex: sampleIndex
            )
        }
        let current = history.last ?? dockerStatsJSONObject(
            shortID: shortID,
            fullID: fullID,
            name: name,
            sampleIndex: 0
        )
        return [
            "id": fullID,
            "name": name,
            "image": "postgres:17",
            "status": "Up 2 hours (healthy)",
            "ports": "0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp",
            "project": "/Users/example/src/project-\(index)",
            "agent": "codex",
            "role": "database",
            "metadata_source": "docker_labels",
            "adopted": false,
            "stats": current,
            "stats_history": history,
        ]
    }
    var data = try JSONSerialization.data(
        withJSONObject: inventoryJSONObject(
            home: home,
            containers: containers,
            postgres: Array(containers.prefix(9))
        ),
        options: [.prettyPrinted, .sortedKeys]
    )
    data.append(0x0A)
    return data
}

private func inventoryJSONObject(
    home: String,
    containers: [[String: Any]],
    postgres: [[String: Any]]
) -> [String: Any] {
    [
        "coordinator_home": home,
        "state_path": "\(home)/state.json",
        "urls": [],
        "servers": [],
        "leases": [],
        "recent_events": [],
        "docker": [
            "available": true,
            "containers": containers,
            "postgres": postgres,
        ],
        "postgres": postgres,
        "backups": [],
        "project_usage": [],
    ]
}

private func dockerStatsJSONObject(
    shortID: String,
    fullID: String,
    name: String,
    sampleIndex: Int
) -> [String: Any] {
    [
        "id": shortID,
        "container_id": fullID,
        "name": name,
        "timestamp": String(format: "2026-07-13T12:%02d:00Z", sampleIndex % 60),
        "timestamp_ts": 1_783_944_000.0 + Double(sampleIndex),
        "live": true,
        "cpu_percent": 17.25,
        "memory_percent": 3.75,
        "memory_usage_bytes": 123_456_789.0,
        "memory_limit_bytes": 34_359_738_368.0,
        "network_rx_bytes": 1_234_567.0,
        "network_tx_bytes": 7_654_321.0,
        "block_read_bytes": 1_048_576.0,
        "block_write_bytes": 2_097_152.0,
        "network_rx_rate_bytes_per_second": 1_024.5,
        "network_tx_rate_bytes_per_second": 2_048.5,
        "block_read_rate_bytes_per_second": 512.25,
        "block_write_rate_bytes_per_second": 256.25,
        "pids": 12,
    ]
}

private func inventoryExecution(home: String, serverName: String, project: String? = nil) -> CommandExecution {
    let projectJSON = project.map { ",\"project\":\"\($0)\"" } ?? ""
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":[{"id":"same-native-id","name":"\(serverName)"\(projectJSON),"status":"running","health":{"ok":true,"pid_alive":true}}],"leases":[],"recent_events":[],"docker":{"containers":[],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}
    """
    return CommandExecution(stdout: json, stderr: "", exitStatus: 0)
}

private func selectionRepository(named name: String) throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("\(name)-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: root.appendingPathComponent(".git", isDirectory: true),
        withIntermediateDirectories: true
    )
    return root
}

private func selectionContainerInventoryExecution(
    home: String,
    project: String,
    postgres: Bool
) -> CommandExecution {
    let name = postgres ? "selection-postgres" : "selection-worker"
    let image = postgres ? "postgres:17" : "worker:latest"
    let container = """
    {"id":"immutable-selection-container","name":"\(name)","image":"\(image)","status":"Up","project":"\(project)","metadata_source":"coordinator_sidecar"}
    """
    let postgresRows = postgres ? "[\(container)]" : "[]"
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"available":true,"containers":[\(container)],"postgres":\(postgresRows)},"postgres":\(postgresRows),"backups":[],"project_usage":[]}
    """
    return CommandExecution(stdout: json, stderr: "", exitStatus: 0)
}

private func threeSourceRepositoryInventoryExecution(
    home: String,
    project: String,
    includeServers: Bool,
    sample: Int
) -> CommandExecution {
    let servers = includeServers
        ? """
          [{"id":"nevod-web","name":"web","project":"\(project)","port":3000,"status":"stopped"},{"id":"nevod-worker","name":"worker","project":"\(project)","port":3001,"status":"stopped"}]
          """
        : "[]"
    let serverIDs = includeServers ? #"["nevod-web","nevod-worker"]"# : "[]"
    let timestamp = 1_783_944_000 + sample
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":\(servers),"leases":[],"recent_events":[],"docker":{"available":true,"containers":[{"id":"nevod-worker-container","name":"nevod-telegram-worker","project":"\(project)","status":"Up","metadata_source":"docker_labels","stats":{"container_id":"nevod-worker-container","timestamp_ts":\(timestamp),"live":true,"cpu_percent":0.6,"memory_usage_bytes":100000000}},{"id":"nevod-postgres-container","name":"nevod-postgres","project":"\(project)","status":"Up","metadata_source":"docker_labels","stats":{"container_id":"nevod-postgres-container","timestamp_ts":\(timestamp),"live":true,"cpu_percent":2.0,"memory_usage_bytes":3600000000}}],"postgres":[]},"postgres":[],"backups":[],"project_usage":[{"usage_key":"path:\(project)","project":"\(project)","project_key":"nevod","name":"Nevod","server_ids":\(serverIDs),"container_names":["nevod-telegram-worker","nevod-postgres"],"server_count":\(includeServers ? 2 : 0),"container_count":2,"process_count":0,"cpu_percent":2.6,"memory_bytes":3700000000,"hot_processes":[]}]}
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

private func dockerProjectConflictInventoryExecution(home: String, project: String) -> CommandExecution {
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"available":true,"containers":[{"id":"shared-conflicting-container","name":"shared-worker","status":"Up","project":"\(project)","metadata_source":"coordinator_sidecar"}],"postgres":[]},"postgres":[],"backups":[],"project_usage":[{"usage_key":"path:\(project)","project":"\(project)","project_key":"\(URL(fileURLWithPath: project).lastPathComponent)","name":"\(URL(fileURLWithPath: project).lastPathComponent)","server_ids":[],"container_names":["shared-worker"],"server_count":0,"container_count":1,"process_count":0,"cpu_percent":0,"memory_bytes":0}]}
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

private struct StaticDatabaseDiscovery: DatabaseDiscovering {
    let database: String
    let sizeBytes: Int64

    func discover(origin: CoordinatorOrigin, container: String, containerID: String?) async throws -> [DiscoveredDatabase] {
        [
            DiscoveredDatabase(
                identity: DatabaseIdentity(
                    origin: origin,
                    container: container,
                    database: database,
                    containerID: containerID
                ),
                sizeBytes: sizeBytes
            )
        ]
    }
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

private actor DelayedCountingCoordinatorService: CoordinatorServing {
    private let result: CommandExecution
    private let delay: Duration
    private var calls = 0

    init(result: CommandExecution, delay: Duration) {
        self.result = result
        self.delay = delay
    }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        guard arguments.first == "inventory" else { throw MockFailure.offline }
        calls += 1
        try await Task.sleep(for: delay)
        return result
    }

    func callCount() -> Int { calls }
}

private actor GatedSequencedCoordinatorService: CoordinatorServing {
    private var outcomes: [Result<CommandExecution, MockFailure>]
    private var startedCalls = 0
    private var continuations: [Int: CheckedContinuation<Void, Never>] = [:]

    init(results: [CommandExecution]) {
        outcomes = results.map(Result.success)
    }

    init(outcomes: [Result<CommandExecution, MockFailure>]) {
        self.outcomes = outcomes
    }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        guard arguments.first == "inventory", !outcomes.isEmpty else { throw MockFailure.offline }
        startedCalls += 1
        let call = startedCalls
        await withCheckedContinuation { continuation in
            continuations[call] = continuation
        }
        return try outcomes.removeFirst().get()
    }

    func startedCallCount() -> Int { startedCalls }

    func release(call: Int) {
        continuations.removeValue(forKey: call)?.resume()
    }
}

private final class MutableTestClock: Clock, @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(_ value: Date) {
        self.value = value
    }

    func now() -> Date {
        lock.withLock { value }
    }

    func advance(by interval: TimeInterval) {
        lock.withLock { value = value.addingTimeInterval(interval) }
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

private struct ConfigurationWriterFixtureFailure: Error, CustomStringConvertible {
    let description: String
}

private struct ConfigurationWriterFixtureProcess {
    let process: Process
    let standardOutput: Pipe
    let standardError: Pipe
}

private func launchConfigurationWriterFixture(
    configurationURL: URL,
    configuration: CoordinatorConfiguration,
    eventDirectory: URL
) throws -> ConfigurationWriterFixtureProcess {
    guard configuration.sources.count == 1, let source = configuration.sources.first else {
        throw ConfigurationWriterFixtureFailure(description: "writer fixture requires exactly one source")
    }
    var environment = ProcessInfo.processInfo.environment
    environment["DEVOPS_BOARD_CONFIGURATION_WRITER_FIXTURE"] = "1"
    environment["DEVOPS_BOARD_CONFIGURATION_WRITER_PATH"] = configurationURL.path
    environment["DEVOPS_BOARD_CONFIGURATION_WRITER_LABEL"] = source.label
    environment["DEVOPS_BOARD_CONFIGURATION_WRITER_HOME"] = source.home
    environment["DEVOPS_BOARD_CONFIGURATION_WRITER_ENABLED"] = source.enabled ? "1" : "0"
    environment["DEVOPS_BOARD_CONFIGURATION_WRITER_REFRESH_MODE"] = configuration.refreshPolicy.mode.rawValue
    if let interval = configuration.refreshPolicy.intervalSeconds {
        environment["DEVOPS_BOARD_CONFIGURATION_WRITER_REFRESH_INTERVAL"] = String(interval)
    }
    environment["DEVOPS_BOARD_CONFIGURATION_WRITER_EVENTS"] = eventDirectory.path

    let process = Process()
    let standardOutput = Pipe()
    let standardError = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
    process.arguments = [
        "xctest",
        "-XCTest",
        "DevOpsBoardTests.CoreTests/testConfigurationWriterProcessFixture",
        Bundle(for: CoreTests.self).bundleURL.path,
    ]
    process.environment = environment
    process.standardOutput = standardOutput
    process.standardError = standardError
    do {
        try process.run()
    } catch {
        throw ConfigurationWriterFixtureFailure(description: "could not launch writer fixture: \(error.localizedDescription)")
    }
    return ConfigurationWriterFixtureProcess(
        process: process,
        standardOutput: standardOutput,
        standardError: standardError
    )
}

private func createFixtureMarker(_ url: URL) throws {
    if FileManager.default.createFile(atPath: url.path, contents: Data()) { return }
    guard FileManager.default.fileExists(atPath: url.path) else {
        throw ConfigurationWriterFixtureFailure(description: "could not create fixture marker at \(url.path)")
    }
}

private func waitForFile(_ url: URL, timeout: TimeInterval = 5) throws {
    let deadline = Date().addingTimeInterval(timeout)
    while !FileManager.default.fileExists(atPath: url.path) {
        guard Date() < deadline else {
            throw ConfigurationWriterFixtureFailure(description: "timed out waiting for \(url.lastPathComponent)")
        }
        Thread.sleep(forTimeInterval: 0.01)
    }
}

private func waitForConfigurationWriter(
    _ fixture: ConfigurationWriterFixtureProcess,
    timeout: TimeInterval = 10
) throws {
    let deadline = Date().addingTimeInterval(timeout)
    while fixture.process.isRunning, Date() < deadline {
        Thread.sleep(forTimeInterval: 0.01)
    }
    guard !fixture.process.isRunning else {
        fixture.process.terminate()
        throw ConfigurationWriterFixtureFailure(description: "writer fixture did not exit after release")
    }
    let outputData = fixture.standardOutput.fileHandleForReading.readDataToEndOfFile()
    let errorData = fixture.standardError.fileHandleForReading.readDataToEndOfFile()
    guard fixture.process.terminationStatus == 0 else {
        let output = String(data: outputData, encoding: .utf8) ?? ""
        let error = String(data: errorData, encoding: .utf8) ?? ""
        throw ConfigurationWriterFixtureFailure(
            description: "writer fixture exited \(fixture.process.terminationStatus). stdout: \(output) stderr: \(error)"
        )
    }
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
