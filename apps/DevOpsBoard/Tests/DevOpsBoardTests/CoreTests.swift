import Foundation
import XCTest
@testable import DevOpsBoard

final class CoreTests: XCTestCase {
    private let codex = CoordinatorOrigin(label: "Codex", home: "/tmp/codex-home")
    private let parall = CoordinatorOrigin(label: "Parall", home: "/tmp/parall-home")

    func testConsoleLayoutConsumesTheWindowExactlyWithoutPaneOverlapOrCenterCropping() {
        for width in [1_180.0, 1_440.0, 1_920.0] {
            let layout = consoleLayout(
                totalWidth: width,
                sidebarPreference: defaultSidebarWidth,
                inspectorPreference: minimumInspectorWidth
            )
            let handles = splitHandleWidth * (layout.showsInspector ? 2 : (layout.showsMain ? 1 : 0))
            let occupied = layout.sidebarWidth
                + (layout.showsMain ? layout.mainWidth : 0)
                + (layout.showsInspector ? layout.inspectorWidth : 0)
                + handles

            XCTAssertEqual(occupied, width, accuracy: 0.001)
            XCTAssertGreaterThanOrEqual(layout.mainWidth, minimumMainWidth)
            XCTAssertGreaterThanOrEqual(layout.inspectorWidth, minimumInspectorWidth)
        }
    }

    func testConsoleLayoutDropsTheInspectorBeforeCompressingTheMainPaneBelowReadableWidth() {
        let layout = consoleLayout(
            totalWidth: 1_000,
            sidebarPreference: defaultSidebarWidth,
            inspectorPreference: minimumInspectorWidth
        )

        XCTAssertTrue(layout.showsMain)
        XCTAssertFalse(layout.showsInspector)
        XCTAssertEqual(
            layout.sidebarWidth + splitHandleWidth + layout.mainWidth,
            1_000,
            accuracy: 0.001
        )
        XCTAssertGreaterThanOrEqual(layout.mainWidth, minimumCompactMainWidth)
    }

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

    func testProductionCoordinatorObservationCarriesActorProjectAndFreshnessProvenance() async throws {
        let executor = RecordingCommandExecutor(result: .init(stdout: #"{"status":"completed"}"#, stderr: "", exitStatus: 0))
        let script = "/repo/skills/codex-dev-coordinator/scripts/dev_coordinator.py"
        let service = PythonCoordinatorService(executor: executor, scriptPath: script)

        _ = try await service.observe(origin: codex, maxAgeSeconds: 17)

        let requests = await executor.capturedRequests()
        let request = try XCTUnwrap(requests.first)
        XCTAssertEqual(request.environment["CODEX_AGENT_COORDINATOR_HOME"], codex.home)
        XCTAssertEqual(request.arguments.prefix(3), ["python3", script, "observe"])
        XCTAssertTrue(request.arguments.containsSubsequence(["--agent", NSUserName()]))
        XCTAssertTrue(request.arguments.containsSubsequence(["--project", "/repo"]))
        XCTAssertTrue(request.arguments.containsSubsequence(["--max-age-seconds", "17.0"]))
        XCTAssertTrue(request.arguments.contains("--compact-json"))
    }

    @MainActor
    func testNormalizedRefreshObservesOnceThenReadsInventoryWithoutRediscoveringDatabases() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let accountHome = root.appendingPathComponent("account", isDirectory: true)
        try FileManager.default.createDirectory(at: accountHome, withIntermediateDirectories: true)
        let service = NormalizedObservationCoordinatorService()
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: MustNotRunDatabaseDiscovery(),
            originDiscovery: AccountCoordinatorOriginDiscovery(
                environment: [:],
                accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { accountHome.path })
            ),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .interval(seconds: 30))
            )
        )

        await store.loadInventory(force: true)

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls, ["observe:0.0", "inventory --compact-json --stats-history-limit 30"])
        let database = try XCTUnwrap(store.inventory.postgres.first)
        XCTAssertEqual(database.database, "app")
        XCTAssertEqual(database.databaseSizeBytes, 4_096)
        XCTAssertNil(database.databaseDiscoveryError)
    }

    @MainActor
    func testFirstLoadReadsCommittedInventoryWhenLiveObservationFails() async throws {
        let service = FailingObservationCoordinatorService()
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: MustNotRunDatabaseDiscovery(),
            originDiscovery: AccountCoordinatorOriginDiscovery(
                environment: [:],
                accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { "/tmp/account" })
            ),
            configurationStore: StaticConfigurationStore(
                configuration: CoordinatorConfiguration(refreshPolicy: .manual())
            )
        )

        await store.loadInventory(force: true)

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls, ["observe:0.0", "inventory --compact-json --stats-history-limit 30"])
        XCTAssertEqual(store.sourceStates.first?.phase, .loaded)
        XCTAssertEqual(store.inventory.servers.map(\.name), ["web"])
        XCTAssertEqual(store.capabilityStates.first { $0.capability == .coordinator }?.phase, .available)
        XCTAssertEqual(store.inventoryIssue?.title, "Live inventory refresh unavailable")
        XCTAssertEqual(
            store.inventoryIssue?.summary,
            "Showing the last committed inventory; live host observation failed"
        )
        XCTAssertTrue(
            store.inventoryIssue?.details.localizedCaseInsensitiveContains(
                "injected bounded Docker observation failure"
            ) == true
        )
    }

    func testDirectV2ProjectionUsesDurableIdentitiesAndIgnoresEveryPoisonedV1Field() throws {
        let execution = try directV2InventoryExecution(home: codex.home)
        let graph = try JSONDecoder().decode(
            NormalizedInventoryGraph.self,
            from: Data(execution.stdout.utf8)
        )
        let projection = try graph.boardProjection(origin: codex)

        XCTAssertEqual(projection.catalog.repositories.count, 1)
        XCTAssertEqual(projection.catalog.repositories.first?.identity.repoID, "repo-1")
        XCTAssertEqual(projection.catalog.repositories.first?.displayName, "Repo")
        let groups = makeProjectGroups(from: projection.catalog, inventory: projection.inventory)
        XCTAssertEqual(groups.map(\.id), ["repo:repo-1"])
        XCTAssertFalse(groups.contains { $0.name == "Nevod" })
        XCTAssertEqual(projection.inventory.servers.map(\.name), ["web"])
        XCTAssertEqual(projection.inventory.servers.first?.port, 4_317)
        XCTAssertEqual(projection.inventory.servers.first?.leaseID, "lease-1")
        XCTAssertEqual(projection.inventory.leases.map(\.id), ["lease-1"])

        let docker = try XCTUnwrap(projection.inventory.docker.containers.first)
        XCTAssertTrue(docker.ports?.contains("127.0.0.1:5433->5432/tcp") == true)
        XCTAssertEqual(docker.statsHistory?.map(\.cpuPercent), [11.0, 22.0])
        XCTAssertEqual(docker.stats?.cpuPercent, 22.0)
        let database = try XCTUnwrap(projection.inventory.postgres.first)
        XCTAssertEqual(database.database, "app")
        XCTAssertEqual(database.databaseSizeBytes, 8_192)
        XCTAssertNil(database.databaseDiscoveryError)

        let records = projection.inventory.backups.compactMap { $0.manifestRecord() }
        XCTAssertEqual(records.filter(\.isStronglyVerified).map(\.path), ["/backups/strong.dump"])
        XCTAssertFalse(projection.inventory.backups.contains { $0.path.hasPrefix("/poison/") })
    }

    func testDirectV2ProjectionOmitsExpiredActiveLeaseButKeepsCurrentLeases() throws {
        var object = directV2GraphJSONObject(home: codex.home)
        var leases = try XCTUnwrap(object["leases"] as? [[String: Any]])
        var expired = try XCTUnwrap(leases.first)
        expired["lease_id"] = "lease-expired"
        expired["expires_at"] = "2026-07-18T11:59:59Z"
        var future = expired
        future["lease_id"] = "lease-future"
        future["expires_at"] = "2026-07-18T12:00:01Z"
        var nonExpiring = expired
        nonExpiring["lease_id"] = "lease-no-expiry"
        nonExpiring["expires_at"] = NSNull()
        leases = [expired, future, nonExpiring]
        object["leases"] = leases
        let now = try XCTUnwrap(parseISOTimestamp("2026-07-18T12:00:00Z"))

        let projection = try directV2Projection(
            from: object,
            origin: codex,
            now: now
        )

        XCTAssertEqual(
            projection.inventory.leases.map(\.id),
            ["lease-future", "lease-no-expiry"]
        )
        XCTAssertEqual(projection.inventory.servers.first?.leaseID, "lease-future")
    }

    func testDirectV2ProjectionDoesNotReuseAnInactivePortAssignment() throws {
        var object = directV2GraphJSONObject(home: codex.home)
        var assignments = try XCTUnwrap(object["port_assignments"] as? [[String: Any]])
        assignments[0]["status"] = "inactive"
        object["port_assignments"] = assignments
        object["leases"] = []

        let projection = try directV2Projection(from: object, origin: codex)

        XCTAssertNil(projection.inventory.servers.first?.port)
    }

    func testDirectV2ProjectionMatchesCaseDistinctPortAssignmentsExactly() throws {
        var object = directV2GraphJSONObject(home: codex.home)

        var resources = try XCTUnwrap(object["resources"] as? [String: Any])
        var definitions = try XCTUnwrap(resources["servers"] as? [[String: Any]])
        var secondDefinition = try XCTUnwrap(definitions.first)
        secondDefinition["server_definition_id"] = "server-definition-2"
        secondDefinition["name"] = "Web"
        secondDefinition["role"] = "case-distinct-web"
        secondDefinition["definition_fingerprint"] = "server-definition-fingerprint-2"
        definitions.append(secondDefinition)
        resources["servers"] = definitions
        object["resources"] = resources

        var observations = try XCTUnwrap(object["observations"] as? [String: Any])
        var serverObservations = try XCTUnwrap(observations["servers"] as? [[String: Any]])
        var secondObservation = try XCTUnwrap(serverObservations.first)
        secondObservation["server_definition_id"] = "server-definition-2"
        secondObservation["source_resource_id"] = "legacy-server-row-78"
        serverObservations.append(secondObservation)
        observations["servers"] = serverObservations
        object["observations"] = observations

        var memberships = try XCTUnwrap(object["memberships"] as? [[String: Any]])
        memberships.append([
            "membership_id": "server-membership-2",
            "repo_id": "repo-1",
            "resource_kind": "server",
            "host_resource_id": "server-definition-2",
            "immutable_fingerprint": "server-fingerprint-2",
            "control_binding_id": "server-binding-2",
        ])
        object["memberships"] = memberships

        var bindings = try XCTUnwrap(object["control_bindings"] as? [[String: Any]])
        bindings.append([
            "binding_id": "server-binding-2",
            "repo_id": "repo-1",
            "source_resource_id": "legacy-server-row-78",
            "resource_kind": "server",
            "resource_id": "server-definition-2",
            "source_id": "imported-source",
            "capability": "lifecycle",
            "provenance": "imported_legacy",
            "authority_state": "authoritative",
            "priority": 100,
            "generation": 4,
        ])
        object["control_bindings"] = bindings

        var assignments = try XCTUnwrap(object["port_assignments"] as? [[String: Any]])
        assignments.append([
            "assignment_id": "assignment-2",
            "repo_id": "repo-1",
            "server_name": "Web",
            "port": 4_318,
            "status": "active",
        ])
        object["port_assignments"] = assignments

        let projection = try directV2Projection(from: object, origin: codex)
        let portsByName = Dictionary(
            uniqueKeysWithValues: projection.inventory.servers.map { ($0.name, $0.port) }
        )

        XCTAssertEqual(portsByName["web"], 4_317)
        XCTAssertEqual(portsByName["Web"], 4_318)
    }

    func testRepositoryControlRequiresCompleteAuthoritativeMembershipCoverage() throws {
        let completeProjection = try directV2Projection(
            from: directV2GraphJSONObject(home: codex.home),
            origin: codex
        )
        let completeRepository = try XCTUnwrap(completeProjection.catalog.repositories.first)
        XCTAssertEqual(completeRepository.controlOrigin, codex)
        XCTAssertFalse(completeRepository.projectActionsBlocked)

        for missingResourceKind in ["server", "container"] {
            var object = directV2GraphJSONObject(home: codex.home)
            var memberships = try XCTUnwrap(object["memberships"] as? [[String: Any]])
            memberships.removeAll { $0["resource_kind"] as? String == missingResourceKind }
            object["memberships"] = memberships

            let projection = try directV2Projection(from: object, origin: codex)
            let repository = try XCTUnwrap(projection.catalog.repositories.first)
            XCTAssertNil(
                repository.controlOrigin,
                "a missing \(missingResourceKind) membership must block whole-project control"
            )
            XCTAssertTrue(repository.projectActionsBlocked)
        }
    }

    func testNonDatabaseDockerResourceRequiresMembershipBeforeProjectControl() throws {
        var object = directV2GraphJSONObject(home: codex.home)
        var resources = try XCTUnwrap(object["resources"] as? [String: Any])
        var dockerResources = try XCTUnwrap(resources["docker"] as? [[String: Any]])
        dockerResources.append([
            "docker_resource_id": "docker-resource-worker",
            "engine_id": "engine-1",
            "full_container_id": "immutable-worker-container",
            "current_name": "worker",
            "image": "worker:latest",
            "created_at": "2026-07-15T11:00:00Z",
            "updated_at": "2026-07-15T12:00:00Z",
        ])
        resources["docker"] = dockerResources
        object["resources"] = resources

        var observations = try XCTUnwrap(object["observations"] as? [String: Any])
        var dockerObservations = try XCTUnwrap(observations["docker"] as? [[String: Any]])
        dockerObservations.append([
            "docker_resource_id": "docker-resource-worker",
            "lifecycle": "stopped",
            "health": "stopped",
            "restart_policy": "no",
            "sampled_at": "2026-07-15T12:00:00Z",
        ])
        observations["docker"] = dockerObservations
        object["observations"] = observations

        var bindings = try XCTUnwrap(object["control_bindings"] as? [[String: Any]])
        bindings.append([
            "binding_id": "docker-binding-worker",
            "repo_id": "repo-1",
            "source_resource_id": "legacy-worker-row-77",
            "resource_kind": "container",
            "resource_id": "docker-resource-worker",
            "source_id": "imported-source",
            "capability": "lifecycle",
            "provenance": "imported_legacy",
            "authority_state": "authoritative",
            "priority": 100,
            "generation": 4,
        ])
        object["control_bindings"] = bindings

        let missingMembership = try directV2Projection(from: object, origin: codex)
        let blockedRepository = try XCTUnwrap(missingMembership.catalog.repositories.first)
        XCTAssertNil(blockedRepository.controlOrigin)
        XCTAssertTrue(blockedRepository.projectActionsBlocked)

        var memberships = try XCTUnwrap(object["memberships"] as? [[String: Any]])
        memberships.append([
            "membership_id": "docker-membership-worker",
            "repo_id": "repo-1",
            "resource_kind": "container",
            "host_resource_id": "docker-resource-worker",
            "immutable_fingerprint": "worker-fingerprint",
            "control_binding_id": "docker-binding-worker",
        ])
        object["memberships"] = memberships

        let completeMembership = try directV2Projection(from: object, origin: codex)
        let controlledRepository = try XCTUnwrap(completeMembership.catalog.repositories.first)
        XCTAssertEqual(controlledRepository.controlOrigin, codex)
        XCTAssertFalse(controlledRepository.projectActionsBlocked)
    }

    func testV1OnlyPayloadCannotMasqueradeAsNormalizedInventory() {
        let payload = Data(
            #"{"schema_version":2,"servers":[],"docker":{"containers":[]},"postgres":[],"backups":[]}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(NormalizedInventoryGraph.self, from: payload))
    }

    @MainActor
    func testRetiredImportedSourceProvenanceStillRoutesOneActionThroughCurrentAccountOrigin() async throws {
        let current = CoordinatorOrigin(label: "Current account", home: "/current/account-store")
        let legacyHome = "/retired/legacy-instance"
        let snapshot = try directV2InventoryExecution(
            home: current.home,
            sourceHome: legacyHome,
            sourceStatus: "retired"
        )
        let service = OriginSequencedCoordinatorService(results: [
            current.id: [
                .success(snapshot),
                .success(.init(stdout: "{}", stderr: "", exitStatus: 0)),
                .success(snapshot),
            ],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: MustNotRunDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [current]),
            configurationStore: StaticConfigurationStore(configuration: .init(refreshPolicy: .manual()))
        )

        await store.loadInventory(force: true)
        let container = try XCTUnwrap(store.inventory.docker.containers.first)
        XCTAssertEqual(container.origin, current)
        XCTAssertNil(container.ownershipError)
        store.restartDocker(container)
        try await waitUntil {
            store.actionResults.values.contains { $0.request.kind == .restartDocker && $0.phase == .succeeded }
        }

        let calls = await service.capturedCalls()
        let action = try XCTUnwrap(calls.first { $0.1.prefix(2) == ["docker", "restart"] })
        XCTAssertEqual(action.0, current)
        XCTAssertFalse(calls.contains { $0.0.home == legacyHome })
        XCTAssertEqual(store.sourceStates.map(\.origin), [current])
    }

    func testRunningDisabledRepositoryResourceIsOnlyAnExactUnassignedFenceViolation() throws {
        var object = directV2GraphJSONObject(home: codex.home)
        object["repositories"] = []
        object["memberships"] = []
        object["leases"] = []
        object["port_assignments"] = []
        object["database_backups"] = []
        object["control_bindings"] = []
        var resources = try XCTUnwrap(object["resources"] as? [String: Any])
        resources["servers"] = []
        resources["databases"] = []
        object["resources"] = resources
        var observations = try XCTUnwrap(object["observations"] as? [String: Any])
        observations["servers"] = []
        observations["databases"] = []
        object["observations"] = observations
        let violation: [String: Any] = [
            "unassigned_id": "fence-violation-1",
            "resource_kind": "container",
            "resource_id": "docker-resource-1",
            "display_name": "pg",
            "reason_code": "start_fence_violated",
            "explanation": "A resource from a disabled repository is running.",
            "observed_by": ["host-observer"],
            "controller": "retired-binding",
            "host_resource_id": "docker-resource-1",
            "immutable_fingerprint": "docker-fingerprint",
            "control_binding_id": "retired-binding",
            "ownership_fingerprint": "retired-ownership",
            "can_attach": false,
            "can_retire": true,
            "lifecycle_violation": true,
            "recommended_next_step": "Retire this exact resource.",
        ]
        object["unassigned_resources"] = [violation]
        object["lifecycle_violations"] = [violation]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let projection = try JSONDecoder()
            .decode(NormalizedInventoryGraph.self, from: data)
            .boardProjection(origin: codex)

        XCTAssertTrue(projection.catalog.repositories.isEmpty)
        let unassigned = try XCTUnwrap(projection.catalog.unassigned.docker.first?.representative)
        XCTAssertEqual(unassigned.attribution?.reasonCode, .startFenceViolated)
        XCTAssertTrue(unassigned.attribution?.lifecycleViolation == true)
        XCTAssertNotNil(unassigned.ownershipError, "ordinary lifecycle actions must stay blocked")
        let exact = try XCTUnwrap(unassigned.exactUnassignedResource)
        XCTAssertFalse(unassigned.attribution?.canAttach == true)
        XCTAssertTrue(unassigned.attribution?.canRetire == true)
        XCTAssertEqual(exact.hostResourceID, "docker-resource-1")
        let groups = makeProjectGroups(from: projection.catalog, inventory: projection.inventory)
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups.first?.kind, .unassigned)
        XCTAssertTrue(groups.first?.projectActionsBlocked == true)
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
        XCTAssertEqual(
            store.sourceStates.map(\.origin.statePath),
            ["\(codex.home)/coordinator.sqlite3", "\(parall.home)/coordinator.sqlite3"]
        )
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
            account.id: [.success(accountInventory), .success(accountInventory)],
            chatGPT.id: [.success(chatInventory), .success(chatInventory)],
            codexTT.id: [.success(codexInventory), .success(successfulStart), .success(codexInventory)],
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
            await service.capturedCalls().count == 7
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
            parall.id: [
                .success(owned),
                .success(.init(stdout: "{}", stderr: "", exitStatus: 0)),
                .success(owned),
            ],
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
        try await waitUntil {
            store.actionResults.values.contains { $0.request.kind == .restartDocker && $0.phase == .succeeded }
        }
        let calls = await service.capturedCalls()
        let action = try XCTUnwrap(calls.first { $0.1.prefix(2) == ["docker", "restart"] })
        XCTAssertEqual(action.0.id, parall.id)
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
        let attention = store.resourceAttentionItems
        XCTAssertEqual(attention.count, 1, "one physical conflict must produce one attention item")
        let conflictAttention = try XCTUnwrap(attention.first)
        XCTAssertEqual(conflictAttention.kind, .projectConflict)
        XCTAssertEqual(conflictAttention.title, "shared-worker has conflicting project ownership")
        XCTAssertTrue(conflictAttention.reason.contains("left-owner"))
        XCTAssertTrue(conflictAttention.reason.contains("right-owner"))
        XCTAssertEqual(conflictAttention.reviewTarget.kind, .docker)
        XCTAssertEqual(conflictAttention.reviewTarget.selectionID, "container:shared-conflicting-container")
        XCTAssertEqual(store.healthSummary.level, .unhealthy)
        XCTAssertEqual(store.healthSummary.unhealthyResourceCount, 1)
        XCTAssertEqual(store.presentationSnapshot.level, .unhealthy)
        XCTAssertEqual(store.presentationSnapshot.attentionItemCount, 1)
        XCTAssertNotEqual(store.presentationSnapshot.statusTitle, store.presentationSnapshot.statusMessage)
        XCTAssertTrue(store.reviewAttentionItem(conflictAttention))
        XCTAssertEqual(store.selectedDockerID, conflictAttention.reviewTarget.selectionID)

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
    func testMembershipConflictWithOneStaleParticipantDoesNotAssertCurrentResourceAttention() async throws {
        let fixtureRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("core-stale-docker-conflict-\(UUID().uuidString)", isDirectory: true)
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
        let leftInventory = dockerProjectConflictInventoryExecution(home: codex.home, project: leftProject.path)
        let rightInventory = dockerProjectConflictInventoryExecution(home: parall.home, project: rightProject.path)
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(leftInventory), .success(leftInventory)],
            parall.id: [.success(rightInventory), .failure(MockFailure.offline)],
        ])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex, parall]),
            configurationStore: StaticConfigurationStore()
        )

        await store.loadInventory(force: true)
        XCTAssertEqual(store.resourceAttentionItems.count, 1)

        await store.loadInventory(force: true)
        XCTAssertEqual(store.sourceStates.first(where: { $0.origin.id == parall.id })?.phase, .stale)
        XCTAssertEqual(
            store.repositoryCatalog.repositories.flatMap(\.dockerMembershipConflicts).count,
            2,
            "retained inventory remains visible for diagnostics"
        )
        XCTAssertTrue(
            store.resourceAttentionItems.isEmpty,
            "a contradiction whose second participant is stale is not a current resource assertion"
        )
        XCTAssertEqual(store.healthSummary.unhealthyResourceCount, 0)
        XCTAssertEqual(store.healthSummary.level, .degraded)
    }

    @MainActor
    func testPhysicalServerMembershipConflictProducesOneRoutableAttentionItem() async throws {
        let fixtureRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("core-server-conflict-\(UUID().uuidString)", isDirectory: true)
        let leftProject = fixtureRoot.appendingPathComponent("left-owner", isDirectory: true)
        let rightProject = fixtureRoot.appendingPathComponent("right-owner", isDirectory: true)
        for project in [leftProject, rightProject] {
            try FileManager.default.createDirectory(
                at: project.appendingPathComponent(".git", isDirectory: true),
                withIntermediateDirectories: true
            )
        }
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }
        let leftInventory = serverProjectConflictInventoryExecution(home: codex.home, project: leftProject.path)
        let rightInventory = serverProjectConflictInventoryExecution(home: parall.home, project: rightProject.path)
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

        XCTAssertEqual(store.repositoryCatalog.repositories.flatMap(\.serverMembershipConflicts).count, 2)
        let attention = try XCTUnwrap(store.resourceAttentionItems.first)
        XCTAssertEqual(store.resourceAttentionItems.count, 1)
        XCTAssertEqual(attention.title, "web has conflicting project ownership")
        XCTAssertEqual(attention.reviewTarget.kind, .server)
        XCTAssertEqual(store.healthSummary.unhealthyResourceCount, 1)
        XCTAssertEqual(store.presentationSnapshot.level, .unhealthy)
        XCTAssertTrue(store.reviewAttentionItem(attention))
        XCTAssertEqual(store.selectedServerID, attention.reviewTarget.selectionID)
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

    @MainActor
    func testStoppedAndStartingServersWithFailedProbeAreNotAttentionOrUnhealthyFilterMatches() throws {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        var stopped = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"stopped","name":"stopped-web","status":"stopped","health":{"ok":false,"pid_alive":false},"stopped_reason":"Stopped by project runtime"}"#.utf8)
        )
        var starting = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"starting","name":"warming-web","status":"starting","health":{"ok":false,"pid_alive":true}}"#.utf8)
        )
        for index in [stopped, starting].indices {
            if index == 0 {
                stopped.origin = codex
                stopped.coordinatorID = "stopped"
                stopped.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "stopped").rawValue
            } else {
                starting.origin = codex
                starting.coordinatorID = "starting"
                starting.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "starting").rawValue
            }
        }
        store.inventory.servers = [stopped, starting]
        store.sourceStates = [.init(origin: codex, phase: .loaded, checkedAt: Date(), resourceCount: 2)]
        store.filter = .unhealthy

        XCTAssertFalse(serverRequiresAttention(stopped))
        XCTAssertFalse(serverRequiresAttention(starting))
        XCTAssertTrue(store.resourceAttentionItems.isEmpty)
        XCTAssertTrue(store.filteredServers.isEmpty)
        XCTAssertEqual(store.healthSummary.level, .nominal)
        XCTAssertEqual(store.presentationSnapshot.level, .nominal)
    }

    @MainActor
    func testRunningProbeFailureAndExplicitFailureStatesProduceActionableStableAttention() throws {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        let documents = [
            #"{"id":"running","name":"web","status":"running","health":{"ok":false,"pid_alive":true}}"#,
            #"{"id":"unhealthy","name":"api","status":"unhealthy","health":{"ok":false,"pid_alive":true}}"#,
            #"{"id":"degraded","name":"worker","status":"degraded","health":{"ok":true,"pid_alive":true}}"#,
            #"{"id":"orphaned","name":"orphan","status":"orphaned","health":{"ok":null,"pid_alive":true}}"#,
        ]
        store.inventory.servers = try documents.map { document in
            var server = try JSONDecoder().decode(ManagedServer.self, from: Data(document.utf8))
            server.origin = codex
            server.coordinatorID = server.id
            server.id = ResourceIdentity(origin: codex, kind: .server, nativeID: server.id).rawValue
            return server
        }
        store.sourceStates = [.init(origin: codex, phase: .loaded, checkedAt: Date(), resourceCount: 4)]
        store.filter = .unhealthy

        let attention = store.resourceAttentionItems
        XCTAssertEqual(attention.count, 4)
        XCTAssertEqual(store.filteredServers.count, 4)
        XCTAssertEqual(store.healthSummary.unhealthyResourceCount, 4)
        XCTAssertEqual(store.presentationSnapshot.level, .unhealthy)
        XCTAssertTrue(attention.allSatisfy { !$0.title.isEmpty && !$0.reason.isEmpty })
        XCTAssertTrue(attention.allSatisfy { !$0.recommendedNextStep.isEmpty })
        XCTAssertEqual(Set(attention.map(\.reviewTarget.stableID)).count, 4)

        let webAttention = try XCTUnwrap(attention.first { $0.title == "web health check failed" })
        XCTAssertTrue(store.reviewAttentionItem(webAttention))
        XCTAssertEqual(store.selectedServerID, webAttention.reviewTarget.selectionID)
    }

    @MainActor
    func testStaleOnlyResourceFailureDoesNotAssertCurrentAttention() throws {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        var server = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"web","name":"web","status":"running","health":{"ok":false,"pid_alive":true}}"#.utf8)
        )
        server.origin = codex
        server.coordinatorID = "web"
        server.id = ResourceIdentity(origin: codex, kind: .server, nativeID: "web").rawValue
        var container = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"worker-id","name":"worker","status":"Restarting (1) 2 seconds ago"}"#.utf8)
        )
        container.origin = codex
        store.inventory.servers = [server]
        store.inventory.docker.containers = [container]
        store.sourceStates = [
            .init(origin: codex, phase: .stale, checkedAt: Date(), resourceCount: 2, error: "refresh failed")
        ]
        store.filter = .unhealthy

        XCTAssertTrue(serverRequiresAttention(server), "the retained row still carries failure-shaped evidence")
        XCTAssertTrue(store.resourceAttentionItems.isEmpty, "stale-only evidence must not assert a current failure")
        XCTAssertTrue(store.filteredServers.isEmpty)
        XCTAssertTrue(store.visibleDockerContainers.isEmpty)
        XCTAssertEqual(store.healthSummary.level, .degraded)
    }

    @MainActor
    func testDismissedActionIssueLeavesFailedActivityWithoutKeepingGlobalHealthRed() {
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: []),
            configurationStore: StaticConfigurationStore()
        )
        store.sourceStates = [.init(origin: codex, phase: .loaded, checkedAt: Date(), resourceCount: 0)]
        let request = ActionRequest(kind: .restartServer, title: "Restart web")
        store.actionResults[request.id] = RetainedActionResult(
            request: request,
            phase: .failed,
            queuedAt: Date(),
            finishedAt: Date(),
            exitStatus: 1,
            stdout: "",
            stderr: "connection refused",
            failure: "connection refused"
        )
        store.actionIssue = OpsIssue(
            kind: .action,
            title: "Restart web failed",
            summary: "Connection refused",
            details: "The coordinator could not restart web.",
            createdAt: Date(),
            relatedActionID: request.id
        )

        XCTAssertEqual(store.presentationSnapshot.level, .unhealthy)
        store.dismissActionIssue()

        XCTAssertEqual(store.actionResults.count, 1, "dismissal must retain Activity evidence")
        XCTAssertEqual(store.healthSummary.failedActionCount, 1)
        XCTAssertEqual(store.healthSummary.level, .nominal)
        XCTAssertEqual(store.presentationSnapshot.level, .nominal)
    }

    func testPresentationPrioritizesConcreteActionThenResourceThenInventoryWithoutDuplicateCopy() {
        let now = Date()
        let nominal = HealthSummary.reduce(
            sources: [.init(origin: codex, phase: .loaded, checkedAt: now, resourceCount: 1)],
            resourceSignals: [],
            actions: [],
            now: now
        )
        let resource = ResourceAttentionItem(
            id: "server-health:web",
            kind: .server,
            title: "web health check failed",
            reason: "The running server returned an unhealthy response.",
            recommendedNextStep: "Review logs.",
            reviewTarget: AttentionReviewTarget(kind: .server, selectionID: "web")
        )
        let inventoryIssue = OpsIssue(
            kind: .inventory,
            title: "One source could not refresh",
            summary: "Codex TT is offline.",
            details: "connection refused",
            createdAt: now
        )
        let actionIssue = OpsIssue(
            kind: .action,
            title: "Restart web failed",
            summary: "RESTART WEB FAILED",
            details: "The coordinator returned exit status 1.",
            createdAt: now
        )

        let actionFirst = OpsPresentationSnapshot.reduce(
            health: nominal,
            sources: [.init(origin: codex, phase: .loaded, checkedAt: now, resourceCount: 1)],
            inventoryIssue: inventoryIssue,
            actionIssue: actionIssue,
            resourceAttentionItems: [resource]
        )
        XCTAssertEqual(actionFirst.statusTitle, actionIssue.title)
        XCTAssertEqual(actionFirst.statusMessage, actionIssue.details)
        XCTAssertNotEqual(actionFirst.statusTitle, actionFirst.statusMessage)

        let resourceNext = OpsPresentationSnapshot.reduce(
            health: nominal,
            sources: actionFirst.sources,
            inventoryIssue: inventoryIssue,
            actionIssue: nil,
            resourceAttentionItems: [resource]
        )
        XCTAssertEqual(resourceNext.statusTitle, resource.title)
        XCTAssertEqual(resourceNext.statusMessage, resource.reason)
        XCTAssertEqual(resourceNext.level, .unhealthy)
        XCTAssertEqual(resourceNext.attentionItemCount, 2)
        XCTAssertEqual(resourceNext.resolutionTargetIDs, ["server:web", "sources"])

        let inventoryLast = OpsPresentationSnapshot.reduce(
            health: nominal,
            sources: actionFirst.sources,
            inventoryIssue: inventoryIssue,
            actionIssue: nil
        )
        XCTAssertEqual(inventoryLast.statusTitle, inventoryIssue.title)
        XCTAssertEqual(inventoryLast.statusMessage, inventoryIssue.summary)
        XCTAssertNotEqual(inventoryLast.statusTitle, inventoryLast.statusMessage)
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
        XCTAssertEqual(
            origins.map(\.home),
            [CoordinatorOrigin(label: "Expected", home: accountCoordinator.path).home]
        )
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

    func testNormalizedAccountDiscoveryNeverPollsLegacyParallHomes() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let accountHome = root.appendingPathComponent("account-home", isDirectory: true)
        let accountCoordinator = accountHome.appendingPathComponent(".codex/agent-coordinator", isDirectory: true)
        let legacy = accountHome.appendingPathComponent(
            "Library/Application Support/Parall/Codex Beta/.codex/agent-coordinator",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: true)
        try Data(#"{"version":2}"#.utf8).write(to: legacy.appendingPathComponent("state.json"))

        let origins = AccountCoordinatorOriginDiscovery(
            environment: ["HOME": legacy.path],
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { accountHome.path })
        ).origins()

        XCTAssertEqual(
            origins.map(\.home),
            [CoordinatorOrigin(label: "Expected", home: accountCoordinator.path).home]
        )
        XCTAssertEqual(origins.map(\.label), ["Local account"])
        XCTAssertFalse(origins.contains { $0.home == legacy.path })
    }

    @MainActor
    func testNormalizedAccountSettingsCannotReintroduceLegacyPollingSources() {
        let accountHome = "/tmp/normalized-account-settings"
        let discovery = AccountCoordinatorOriginDiscovery(
            environment: [:],
            accountHomeResolver: POSIXAccountHomeResolver(resolveAccountHome: { accountHome })
        )
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: discovery,
            configurationStore: StaticConfigurationStore()
        )
        let draft = CoordinatorConfiguration(
            sources: [
                CoordinatorSourceConfiguration(
                    label: "Legacy Parall",
                    home: "/tmp/legacy-parall/.codex/agent-coordinator",
                    enabled: true
                )
            ],
            refreshPolicy: CoordinatorRefreshPolicy(mode: .manual, intervalSeconds: nil)
        )

        XCTAssertTrue(store.usesNormalizedAccountCoordinator)
        XCTAssertTrue(store.saveCoordinatorConfiguration(draft))
        XCTAssertTrue(
            store.coordinatorConfiguration.sources.isEmpty,
            "normalized account mode must not persist a source control that its refresh path ignores"
        )
        XCTAssertEqual(store.coordinatorConfiguration.refreshPolicy.mode, .manual)
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

    func testPythonBackupServiceResolvesAuthorityAndExecutesFromExactRepositoryRoot() async throws {
        let executor = SequencedCommandExecutor(results: [
            .init(stdout: #"{"execution_authority":"broker","repository_id":"repo-1","canonical_root":"/repo"}"#, stderr: "", exitStatus: 0),
            .init(stdout: #"{"status":"available"}"#, stderr: "", exitStatus: 0),
        ])
        let service = PythonBackupService(
            executor: executor,
            scriptPath: "/skills/postgres-docker-backup/scripts/postgres_docker_backup.py"
        )

        let authority = try await service.executionAuthority(
            origin: codex,
            projectRoot: "/repo"
        )
        _ = try await service.execute(
            origin: codex,
            projectRoot: "/repo",
            arguments: ["backup", "--container", "pg"]
        )

        let requests = await executor.capturedRequests()
        XCTAssertEqual(authority, .broker)
        XCTAssertEqual(requests.map(\.currentDirectory), ["/repo", "/repo"])
        XCTAssertEqual(
            requests.map(\.arguments),
            [
                ["python3", "/skills/postgres-docker-backup/scripts/postgres_docker_backup.py", "route"],
                ["python3", "/skills/postgres-docker-backup/scripts/postgres_docker_backup.py", "backup", "--container", "pg"],
            ]
        )
        XCTAssertEqual(
            requests.map { $0.environment["CODEX_AGENT_COORDINATOR_HOME"] },
            [codex.home, codex.home]
        )
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
        store.inventory.postgres = [database]
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        store.backupDatabase(container: database)
        try await Task.sleep(for: .milliseconds(100))

        let calls = await backupService.capturedArguments()
        let projectRoots = await backupService.capturedProjectRoots()
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0].suffix(6), ["--container", "pg", "--database", "app", "--expect-container-id", "aaaaaaaaaaaa"])
        XCTAssertEqual(calls[1], ["verify", "--container", "pg", "--database", "app", "--file", "/repo/.codex-db-backups/app.dump", "--expect-container-id", "aaaaaaaaaaaa", "--test-restore"])
        XCTAssertEqual(projectRoots, ["/repo", "/repo"])
        XCTAssertEqual(store.actionResults.values.first?.phase, .succeeded)
    }

    @MainActor
    func testBrokerDatabaseBackupUsesRepositoryContextWithoutClientPathsOrVerification() async throws {
        let projection = try directV2Projection(
            from: directV2GraphJSONObject(home: codex.home),
            origin: codex
        )
        let database = try XCTUnwrap(projection.inventory.postgres.first)
        let backupService = RecordingBackupService(
            results: [
                .init(
                    stdout: #"{"database_backup_id":"backup-new","database_binding_id":"database-binding-1","docker_resource_id":"docker-resource-1","database_name":"app","verification_status":"strong","status":"available"}"#,
                    stderr: "",
                    exitStatus: 0
                )
            ],
            authority: .broker
        )
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            backupService: backupService,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [])
        )
        store.inventory = projection.inventory
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        store.backupDatabase(container: database)
        try await Task.sleep(for: .milliseconds(100))

        let calls = await backupService.capturedArguments()
        let projectRoots = await backupService.capturedProjectRoots()
        XCTAssertEqual(calls, [[
            "backup",
            "--container", "pg",
            "--database", "app",
            "--expect-container-id", "immutable-pg-container",
        ]])
        XCTAssertFalse(calls.flatMap { $0 }.contains("--out-dir"))
        XCTAssertFalse(calls.flatMap { $0 }.contains("verify"))
        XCTAssertEqual(projectRoots, ["/repo"])
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
        var database = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"aaaaaaaaaaaa","name":"pg","project":"/repo","status":"Up"}"#.utf8)
        )
        database.origin = codex
        database.database = "app"
        store.inventory.postgres = [database]
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        store.restoreDatabase(target: target, backup: weak, confirmation: store.restoreConfirmation(for: target))
        store.restoreDatabase(target: target, backup: wrongContainer, confirmation: store.restoreConfirmation(for: target))
        store.restoreDatabase(target: target, backup: strong, confirmation: "RESTORE something-else")
        let rejectedCalls = await backupService.capturedArguments()
        XCTAssertEqual(rejectedCalls.count, 0)

        store.restoreDatabase(target: target, backup: strong, confirmation: store.restoreConfirmation(for: target))
        try await Task.sleep(for: .milliseconds(100))
        let calls = await backupService.capturedArguments()
        let projectRoots = await backupService.capturedProjectRoots()
        XCTAssertEqual(calls, [[
            "restore", "--container", "pg", "--database", "app", "--file", "/backups/app.dump",
            "--expect-container-id", "aaaaaaaaaaaa", "--confirm-restore", "--safety-out-dir", "/backups/pre-restore",
        ]])
        XCTAssertEqual(projectRoots, ["/repo"])
        XCTAssertEqual(store.actionResults.values.first?.phase, .succeeded)
        XCTAssertTrue(store.actionResults.values.first?.stdout.contains("safety_backup") == true)
        XCTAssertEqual(store.restoreEvidence[target]?.safetyBackupPath, "/backups/safety.dump")
    }

    @MainActor
    func testBrokerRestoreUsesOpaqueBackupIDAndNeverSendsClientArtifactPaths() async throws {
        let projection = try directV2Projection(
            from: directV2GraphJSONObject(home: codex.home),
            origin: codex
        )
        let database = try XCTUnwrap(projection.inventory.postgres.first)
        let target = try XCTUnwrap(database.databaseIdentity)
        let backup = try XCTUnwrap(
            projection.inventory.backups
                .first { $0.normalizedBackupID == "backup-strong" }?
                .manifestRecord()
        )
        let backupService = RecordingBackupService(
            results: [
                .init(
                    stdout: #"{"restore_event_id":"restore-event-1","database_backup_id":"backup-strong","safety_database_backup_id":"backup-safety-1","database_binding_id":"database-binding-1","docker_resource_id":"docker-resource-1","database_name":"app","transactional":true,"status":"restored"}"#,
                    stderr: "",
                    exitStatus: 0
                )
            ],
            authority: .broker
        )
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            backupService: backupService,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [])
        )
        store.inventory = projection.inventory
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        store.restoreDatabase(
            target: target,
            backup: backup,
            confirmation: store.restoreConfirmation(for: target)
        )
        try await Task.sleep(for: .milliseconds(100))

        let calls = await backupService.capturedArguments()
        let projectRoots = await backupService.capturedProjectRoots()
        XCTAssertEqual(calls, [[
            "restore",
            "--container", "pg",
            "--database", "app",
            "--database-backup-id", "backup-strong",
            "--expect-container-id", "immutable-pg-container",
            "--confirm-restore",
        ]])
        let flattened = calls.flatMap { $0 }
        XCTAssertFalse(flattened.contains("--file"))
        XCTAssertFalse(flattened.contains("--safety-out-dir"))
        XCTAssertEqual(projectRoots, ["/repo"])
        XCTAssertEqual(store.actionResults.values.first?.phase, .succeeded)
        XCTAssertNil(store.restoreEvidence[target], "broker registry evidence must not be mislabeled as a client artifact path")
    }

    @MainActor
    func testDatabaseProtectionFailsClosedWhenCurrentOwnershipIsNotAuthoritative() async throws {
        var object = directV2GraphJSONObject(home: codex.home)
        var bindings = try XCTUnwrap(object["control_bindings"] as? [[String: Any]])
        let dockerBindingIndex = try XCTUnwrap(
            bindings.firstIndex { $0["binding_id"] as? String == "docker-binding-1" }
        )
        bindings[dockerBindingIndex]["authority_state"] = "candidate"
        object["control_bindings"] = bindings

        let projection = try directV2Projection(from: object, origin: codex)
        let database = try XCTUnwrap(projection.inventory.postgres.first)
        XCTAssertNotNil(database.ownershipError)
        XCTAssertNil(database.databaseIdentity, "an uncontrolled database must not expose a mutable identity")

        let backupService = RecordingBackupService(results: [])
        let store = OpsStore(
            coordinatorService: OriginSequencedCoordinatorService(results: [:]),
            backupService: backupService,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [])
        )
        store.inventory = projection.inventory
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        XCTAssertFalse(databaseProtectionActionAllowed(store, kind: .backupDatabase, database: database))
        XCTAssertFalse(databaseProtectionActionAllowed(store, kind: .restoreDatabase, database: database))

        var stalePreviouslyControlledDatabase = database
        stalePreviouslyControlledDatabase.ownershipError = nil
        let staleTarget = try XCTUnwrap(stalePreviouslyControlledDatabase.databaseIdentity)
        let strongBackup = BackupRecord(
            identity: staleTarget,
            path: "/backups/app.dump",
            createdAt: Date(),
            checksum: .verified,
            restoreTest: .passed
        )
        store.backupDatabase(container: stalePreviouslyControlledDatabase)
        store.restoreDatabase(
            target: staleTarget,
            backup: strongBackup,
            confirmation: store.restoreConfirmation(for: staleTarget)
        )
        try await Task.sleep(for: .milliseconds(50))

        let calls = await backupService.capturedArguments()
        XCTAssertTrue(calls.isEmpty)
        XCTAssertTrue(store.actionResults.isEmpty, "ownership rejection must happen before an operation is reserved")
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
        let decodedFixture = try JSONDecoder()
            .decode(NormalizedInventoryGraph.self, from: payload)
            .boardProjection(origin: origin)
            .inventory
        let historySamples = decodedFixture.docker.containers.reduce(0) { partial, container in
            partial + (container.statsHistory?.count ?? 0)
        }
        XCTAssertGreaterThan(payload.count, 1_048_576, "the recall fixture must cross the former production limit")
        XCTAssertEqual(decodedFixture.docker.containers.count, 15)
        XCTAssertEqual(decodedFixture.postgres.count, 9)
        XCTAssertEqual(historySamples, 558)
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
            558
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
    func testNormalizedBackupRegistryLoadsInTheSameSnapshotWithoutDuplicatePolling() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(try directV2InventoryExecution(home: codex.home))]
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
        ])
        XCTAssertEqual(store.inventory.docker.containers.first?.name, "pg")
        XCTAssertEqual(store.inventory.docker.containers.first?.stats?.cpuPercent, 22.0)
        XCTAssertEqual(store.inventory.backups.first?.path, "/backups/strong.dump")
    }

    @MainActor
    func testFailedDatabaseObservationRetainsRuntimeSnapshotAndDegradesOnlyDatabaseCapability() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(try directV2InventoryExecution(
                home: codex.home,
                databaseAvailable: false,
                databaseError: "database probe timed out"
            ))]
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
        XCTAssertEqual(store.inventory.docker.containers.first?.name, "pg")
        XCTAssertEqual(store.inventory.docker.containers.first?.stats?.cpuPercent, 22.0)
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .docker }?.phase,
            .available
        )
        XCTAssertEqual(
            store.capabilityStates.first { $0.capability == .database }?.phase,
            .unavailable
        )
        XCTAssertTrue(store.inventoryIssue?.details.localizedCaseInsensitiveContains("database probe timed out") == true)
    }

    @MainActor
    func testDockerAndDatabaseObservationFailuresAreBothRetainedInDiagnostics() async throws {
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(try directV2InventoryExecution(
                home: codex.home,
                dockerCapability: "unavailable",
                databaseAvailable: false,
                databaseError: "database probe timed out"
            ))]
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
        XCTAssertTrue(details.localizedCaseInsensitiveContains("database probe timed out"))
        XCTAssertTrue(details.localizedCaseInsensitiveContains("docker observer is unavailable"))
    }

    @MainActor
    func testInventoryRefreshUsesStrongRegistryWithoutHashingMultiGigabyteBackupArtifacts() async throws {
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
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(try directV2InventoryExecution(
                home: codex.home,
                strongArtifactPath: artifact.path
            ))]
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
        XCTAssertEqual(store.backupRecords.first?.checksum, .verified)
        XCTAssertEqual(store.backupRecords.first?.restoreTest, .passed)
    }

    @MainActor
    func testSelectingDatabaseOffersOnlyStrongAvailableDatabaseScopedRegistryBackup() async throws {
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
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(try directV2InventoryExecution(
                home: codex.home,
                strongArtifactPath: artifact.path
            ))]
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
        XCTAssertEqual(store.backupRecords.first?.checksum, .verified)
        let database = try XCTUnwrap(store.inventory.postgres.first)
        store.selectDatabase(database)

        XCTAssertFalse(store.isBackupVerificationInProgress(for: database))
        let exact = try XCTUnwrap(database.databaseIdentity)
        XCTAssertEqual(newestVerifiedBackup(for: exact, in: store.backupRecords)?.path, artifact.path)
        XCTAssertEqual(store.backupRecords.filter(\.isStronglyVerified).count, 1)
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
        XCTAssertEqual(calls.count, 2, "the failed project command must be followed by one inventory refresh")
        XCTAssertEqual(calls[1].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
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
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[1].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
    }

    @MainActor
    func testRepositoryRemovalPlanCancelHasZeroMutationAndKeepsRepositoryVisible() async throws {
        let plan = CommandExecution(
            stdout: repositoryRemovalPlanJSON(),
            stderr: "",
            exitStatus: 0
        )
        let service = OriginSequencedCoordinatorService(results: [codex.id: [.success(plan)]])
        let store = OpsStore(
            coordinatorService: service,
            commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
            databaseDiscovery: EmptyDatabaseDiscovery(),
            originDiscovery: StaticOriginDiscovery(values: [codex]),
            configurationStore: StaticConfigurationStore()
        )
        var server = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"server-id","name":"web","project":"/repo","status":"running"}"#.utf8)
        )
        server.origin = codex
        store.inventory.servers = [server]
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let group = ProjectGroup(
            id: "path:/repo",
            name: "Repo",
            projectPath: "/repo",
            servers: [server],
            containers: [],
            databases: [],
            usage: nil
        )

        store.planRepositoryDecommission(group)
        try await waitUntil { store.repositoryDecommissionPrompt != nil }
        let callsAfterPlan = await service.capturedCalls()
        XCTAssertEqual(callsAfterPlan.count, 1)
        XCTAssertEqual(callsAfterPlan[0].1.prefix(2), ["repository", "plan-remove"])

        store.cancelRepositoryDecommission()

        XCTAssertNil(store.repositoryDecommissionPrompt)
        XCTAssertEqual(store.inventory.servers.map(\.name), ["web"])
        let callsAfterCancel = await service.capturedCalls()
        XCTAssertEqual(callsAfterCancel.count, 1, "cancel must not call the removal endpoint")
    }

    @MainActor
    func testRepositoryRemovalUsesExactPlanAndHidesOnlyAfterAuthoritativeRefresh() async throws {
        let plan = CommandExecution(stdout: repositoryRemovalPlanJSON(), stderr: "", exitStatus: 0)
        let applied = CommandExecution(
            stdout: #"{"schema_version":1,"operation_id":"operation-remove-1","plan_id":"plan-remove-1","plan_fingerprint":"plan-fingerprint-1","kind":"repository_decommission","repo_id":"repo-1","status":"succeeded","fence":"retained","hidden":true,"started":false,"retained_data":["repository_files","volumes","databases","backups","audit_history"],"targets":[{"target_id":"server-target","kind":"server","status":"succeeded","phase":"verified"}],"errors":[]}"#,
            stderr: "",
            exitStatus: 0
        )
        let refreshed = CommandExecution(
            stdout: #"{"coordinator_home":"/tmp/codex-home","state_path":"/tmp/codex-home/coordinator.sqlite3","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"available":true,"containers":[],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}"#,
            stderr: "",
            exitStatus: 0
        )
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(plan), .success(applied), .success(refreshed)]
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
            from: Data(#"{"id":"server-id","name":"web","project":"/repo","status":"running"}"#.utf8)
        )
        server.origin = codex
        store.inventory.servers = [server]
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let group = ProjectGroup(
            id: "path:/repo",
            name: "Repo",
            projectPath: "/repo",
            servers: [server],
            containers: [],
            databases: [],
            usage: nil
        )

        store.planRepositoryDecommission(group)
        try await waitUntil { store.repositoryDecommissionPrompt != nil }
        let prompt = try XCTUnwrap(store.repositoryDecommissionPrompt)
        XCTAssertEqual(store.inventory.servers.map(\.name), ["web"], "planning must not hide active inventory")

        store.applyRepositoryDecommission(prompt)
        try await waitUntil {
            store.repositoryDecommissionPrompt == nil
                && store.inventory.servers.isEmpty
                && store.actionResults.values.contains { $0.request.kind == .repositoryDecommission && $0.phase == .succeeded }
        }

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 3)
        XCTAssertEqual(calls[1].1.prefix(2), ["repository", "remove"])
        XCTAssertTrue(calls[1].1.contains("plan-remove-1"))
        XCTAssertTrue(calls[1].1.contains("plan-fingerprint-1"))
        XCTAssertEqual(calls[2].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
    }

    @MainActor
    func testPartialRepositoryRemovalRetainsFencePromptAndFailureEvidence() async throws {
        let plan = CommandExecution(stdout: repositoryRemovalPlanJSON(), stderr: "", exitStatus: 0)
        let partial = CommandExecution(
            stdout: #"{"schema_version":1,"operation_id":"operation-remove-1","plan_id":"plan-remove-1","plan_fingerprint":"plan-fingerprint-1","kind":"repository_decommission","repo_id":"repo-1","status":"needs_attention","fence":"retained","hidden":false,"started":false,"retained_data":["repository_files","volumes","databases"],"targets":[{"target_id":"container-target","kind":"docker","status":"failed","phase":"stop","error":"container remained running"}],"errors":["verification incomplete"]}"#,
            stderr: "",
            exitStatus: 0
        )
        let refreshed = inventoryExecution(home: codex.home, serverName: "still-visible", project: "/repo")
        let service = OriginSequencedCoordinatorService(results: [
            codex.id: [.success(plan), .success(partial), .success(refreshed), .success(refreshed)]
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
            from: Data(#"{"id":"server-id","name":"web","project":"/repo","status":"running"}"#.utf8)
        )
        server.origin = codex
        store.inventory.servers = [server]
        markSourceLoaded(store, origin: codex, resourceCount: 1)
        let group = ProjectGroup(
            id: "path:/repo",
            name: "Repo",
            projectPath: "/repo",
            servers: [server],
            containers: [],
            databases: [],
            usage: nil
        )

        store.planRepositoryDecommission(group)
        try await waitUntil { store.repositoryDecommissionPrompt != nil }
        let prompt = try XCTUnwrap(store.repositoryDecommissionPrompt)
        store.applyRepositoryDecommission(prompt)

        try await waitUntil {
            store.actionResults.values.contains {
                $0.request.kind == .repositoryDecommission && $0.phase == .failed
            } && store.inventory.servers.first?.name == "still-visible"
        }
        XCTAssertNotNil(store.repositoryDecommissionPrompt, "a partial removal must remain visible and retryable")
        XCTAssertTrue(store.actionIssue?.summary.contains("verification incomplete") == true)
        XCTAssertTrue(store.actionIssue?.summary.contains("container remained running") == true)
    }

    func testUnassignedResourceActionsRequireEveryExactIdentityField() throws {
        var complete = try exactUnassignedContainer(origin: codex)
        XCTAssertEqual(complete.exactUnassignedResource?.hostResourceID, "docker:immutable-copy-pg")
        XCTAssertEqual(
            complete.exactUnassignedResource?.identityArguments,
            [
                "--resource-kind", "container",
                "--resource-id", "docker:immutable-copy-pg",
                "--immutable-fingerprint", "container-fingerprint-1",
                "--control-binding-id", "docker-binding-1",
                "--ownership-fingerprint", "ownership-fingerprint-1",
            ]
        )

        complete = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"immutable-copy-pg","name":"kosttracking-prod-copy-pg","status":"running","attribution":{"reason_code":"ambiguous_control","explanation":"No authoritative repository binding","observed_by":["host-observer"],"controller":"docker-binding-1","host_resource_id":"docker:immutable-copy-pg","immutable_fingerprint":"container-fingerprint-1","control_binding_id":"docker-binding-1","can_attach":true,"can_retire":true}}"#.utf8)
        )
        complete.origin = codex
        XCTAssertNil(
            complete.exactUnassignedResource,
            "a missing ownership fingerprint must suppress actions instead of guessing a host target"
        )
    }

    func testActionableUnassignedCopyNamesTheTwoSafeUserDecisions() {
        let presentation = ResourceAttributionPresentation(
            reasonCode: .ambiguousControl,
            explanation: "Observed without repository membership",
            observedBy: ["host-observer"],
            controller: "account coordinator",
            canAttach: true,
            canRetire: true,
            recommendedNextStep: nil
        )

        XCTAssertTrue(presentation.nextStep.contains("attach it"))
        XCTAssertTrue(presentation.nextStep.contains("retire it"))
        XCTAssertTrue(presentation.nextStep.contains("block future automatic starts"))
        XCTAssertTrue(presentation.nextStep.contains("without deleting its data"))
    }

    @MainActor
    func testRunningRemovedResourceBecomesOneCriticalAttentionItemWithoutResurrectingProject() throws {
        var container = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"removed-container-id","name":"removed-copy-pg","status":"running","metadata_source":"normalized_store","attribution":{"reason_code":"start_fence_violated","explanation":"This exact container is running even though its retained removal fence is active.","observed_by":["account coordinator"],"controller":"binding-removed","host_resource_id":"docker:removed-container","immutable_fingerprint":"container-removed-fingerprint","control_binding_id":"binding-removed","ownership_fingerprint":"ownership-removed-fingerprint","can_attach":false,"can_retire":false,"lifecycle_violation":true,"recommended_next_step":"Stop the exact container and resume the retained removal operation."}}"#.utf8)
        )
        container.origin = codex
        var inventory = Inventory.empty
        inventory.docker = DockerSummary(
            available: true,
            error: nil,
            statsError: nil,
            containers: [container],
            postgres: []
        )
        let store = makeExactLifecycleStore(
            service: ExactLifecycleCoordinatorService(results: []),
            origin: codex
        )
        store.inventory = inventory
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        XCTAssertEqual(store.resourceAttentionItems.count, 1)
        let attention = try XCTUnwrap(store.resourceAttentionItems.first)
        XCTAssertEqual(attention.id, "start-fence-violation:docker:\(container.containerSelectionID)")
        XCTAssertEqual(attention.title, "removed-copy-pg is running after removal")
        XCTAssertTrue(attention.reason.contains("retained removal fence"))
        XCTAssertEqual(
            attention.recommendedNextStep,
            "Stop the exact container and resume the retained removal operation."
        )
        XCTAssertEqual(attention.reviewTarget.kind, .docker)
        XCTAssertEqual(store.presentationSnapshot.level, .unhealthy)
        XCTAssertTrue(store.projectGroups.filter(\.isRepository).isEmpty)
        XCTAssertEqual(store.projectGroups.filter { !$0.isRepository }.count, 1)
        XCTAssertEqual(container.attribution?.reasonCode, .startFenceViolated)
        XCTAssertEqual(container.attribution?.lifecycleViolation, true)
        XCTAssertEqual(container.attribution?.canAttach, false)
        XCTAssertEqual(container.attribution?.canRetire, false)
        XCTAssertEqual(
            attributionPresentation(for: container)?.nextStep,
            "Stop the exact container and resume the retained removal operation."
        )
    }

    @MainActor
    func testOrdinaryStoppedUnassignedResourceIsNotAStartFenceViolation() throws {
        var container = try exactUnassignedContainer(origin: codex)
        container.status = "stopped"
        var inventory = Inventory.empty
        inventory.docker = DockerSummary(
            available: true,
            error: nil,
            statsError: nil,
            containers: [container],
            postgres: []
        )
        let store = makeExactLifecycleStore(
            service: ExactLifecycleCoordinatorService(results: []),
            origin: codex
        )
        store.inventory = inventory
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        XCTAssertEqual(container.attribution?.lifecycleViolation, false)
        XCTAssertFalse(store.resourceAttentionItems.contains { $0.id.hasPrefix("start-fence-violation:") })
    }

    @MainActor
    func testRunningRemovedServerBecomesCriticalAttentionWithoutProjectResurrection() throws {
        var server = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(#"{"id":"removed-server-id","name":"web","status":"running","attribution":{"reason_code":"start_fence_violated","explanation":"This exact server is listening while its repository remains removed.","observed_by":["account coordinator"],"controller":"binding-server-removed","host_resource_id":"server:removed","immutable_fingerprint":"server-removed-fingerprint","control_binding_id":"binding-server-removed","ownership_fingerprint":"server-ownership-fingerprint","can_attach":false,"can_retire":false,"lifecycle_violation":true,"recommended_next_step":"Stop the exact server and resume repository removal."}}"#.utf8)
        )
        server.origin = codex
        var inventory = Inventory.empty
        inventory.servers = [server]
        let store = makeExactLifecycleStore(
            service: ExactLifecycleCoordinatorService(results: []),
            origin: codex
        )
        store.inventory = inventory
        markSourceLoaded(store, origin: codex, resourceCount: 1)

        XCTAssertEqual(store.resourceAttentionItems.count, 1)
        let attention = try XCTUnwrap(store.resourceAttentionItems.first)
        XCTAssertEqual(attention.kind, .server)
        XCTAssertEqual(attention.title, "web is running after removal")
        XCTAssertEqual(attention.recommendedNextStep, "Stop the exact server and resume repository removal.")
        XCTAssertEqual(attention.reviewTarget.kind, .server)
        XCTAssertTrue(store.projectGroups.filter(\.isRepository).isEmpty)
    }

    @MainActor
    func testExplicitResourceAttachUsesExactIdentityAndNeverStartsTheResource() async throws {
        let attached = CommandExecution(
            stdout: #"{"schema_version":1,"repo_id":"repo-1","resource_id":"docker:immutable-copy-pg","resource_kind":"container","attached":true,"started":false}"#,
            stderr: "",
            exitStatus: 0
        )
        let service = ExactLifecycleCoordinatorService(results: [attached, emptyNormalizedInventoryExecution()])
        let store = makeExactLifecycleStore(service: service, origin: codex)
        let seeded = try seedExactLifecyclePresentation(store: store, origin: codex)
        defer { try? FileManager.default.removeItem(atPath: seeded.projectPath) }

        store.prepareResourceAttach(seeded.target)
        let prompt = try XCTUnwrap(store.resourceAttachPrompt)
        store.attachResource(prompt, to: seeded.repository)

        try await waitUntil {
            store.resourceAttachPrompt == nil
                && store.actionResults.values.contains { $0.request.kind == .attachResource && $0.phase == .succeeded }
        }

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0].0.id, codex.id)
        XCTAssertTrue(calls[0].1.containsSubsequence(["resource", "attach"]))
        XCTAssertTrue(calls[0].1.containsSubsequence(seeded.target.identityArguments))
        XCTAssertTrue(calls[0].1.containsSubsequence(["--project", seeded.projectPath, "--agent"]))
        XCTAssertFalse(calls[0].1.contains("start"))
        XCTAssertEqual(calls[1].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
    }

    @MainActor
    func testStandaloneRetirementCancelStopsAfterReadOnlyExactPlan() async throws {
        let service = ExactLifecycleCoordinatorService(
            results: [CommandExecution(stdout: standaloneRetirementPlanJSON(), stderr: "", exitStatus: 0)]
        )
        let store = makeExactLifecycleStore(service: service, origin: codex)
        let seeded = try seedExactLifecyclePresentation(store: store, origin: codex)
        defer { try? FileManager.default.removeItem(atPath: seeded.projectPath) }

        store.planResourceRetirement(seeded.target)
        try await waitUntil { store.resourceRetirementPrompt != nil }
        store.cancelResourceRetirement()

        XCTAssertNil(store.resourceRetirementPrompt)
        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 1, "cancel must not execute the retirement plan")
        XCTAssertTrue(calls[0].1.containsSubsequence(["resource", "plan-retire"]))
        XCTAssertTrue(calls[0].1.containsSubsequence(seeded.target.identityArguments))
        XCTAssertTrue(calls[0].1.containsSubsequence(["--request-project", "/workflow/repo"]))
    }

    @MainActor
    func testPartialStandaloneRetirementKeepsFencePromptAndRefreshesTruth() async throws {
        let partial = CommandExecution(
            stdout: #"{"schema_version":1,"operation_id":"retire-operation-1","plan_id":"retire-plan-1","plan_fingerprint":"retire-fingerprint-1","kind":"standalone_resource_retirement","resource_id":"docker:immutable-copy-pg","status":"needs_attention","fence":"retained","hidden":false,"started":false,"retained_data":["containers","volumes","databases","backups","audit_history"],"targets":[{"target_id":"docker:immutable-copy-pg","kind":"container","status":"failed","phase":"verify","error":{"code":"still_running","message":"the exact container remained running","phase":"verify"}}],"errors":[{"code":"verification_incomplete","message":"stop verification is incomplete","phase":"verify"}]}"#,
            stderr: "",
            exitStatus: 0
        )
        let service = ExactLifecycleCoordinatorService(results: [
            CommandExecution(stdout: standaloneRetirementPlanJSON(), stderr: "", exitStatus: 0),
            partial,
            emptyNormalizedInventoryExecution(),
        ])
        let store = makeExactLifecycleStore(service: service, origin: codex)
        let seeded = try seedExactLifecyclePresentation(store: store, origin: codex)
        defer { try? FileManager.default.removeItem(atPath: seeded.projectPath) }

        store.planResourceRetirement(seeded.target)
        try await waitUntil { store.resourceRetirementPrompt != nil }
        let prompt = try XCTUnwrap(store.resourceRetirementPrompt)
        store.applyResourceRetirement(prompt)

        try await waitUntil {
            store.actionResults.values.contains {
                $0.request.kind == .retireStandaloneResource && $0.phase == .failed
            } && store.inventory.servers.isEmpty
        }
        XCTAssertNotNil(
            store.resourceRetirementPrompt,
            "partial retirement must retain the exact plan/fence for a safe retry"
        )
        XCTAssertTrue(store.actionIssue?.summary.contains("stop verification is incomplete") == true)
        XCTAssertTrue(store.actionIssue?.summary.contains("the exact container remained running") == true)

        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 3)
        XCTAssertTrue(calls[1].1.containsSubsequence(["resource", "retire"]))
        XCTAssertTrue(calls[1].1.containsSubsequence(seeded.target.identityArguments))
        XCTAssertTrue(calls[1].1.containsSubsequence(["--plan-id", "retire-plan-1"]))
        XCTAssertTrue(calls[1].1.containsSubsequence(["--plan-fingerprint", "retire-fingerprint-1"]))
        XCTAssertEqual(calls[2].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
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
        var database = try JSONDecoder().decode(
            DockerContainer.self,
            from: Data(#"{"id":"bbbbbbbbbbbb","name":"pg","project":"/repo","status":"Up"}"#.utf8)
        )
        database.origin = codex
        database.database = "app"
        store.inventory.postgres = [database]

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
private func makeExactLifecycleStore(
    service: ExactLifecycleCoordinatorService,
    origin: CoordinatorOrigin
) -> OpsStore {
    OpsStore(
        coordinatorService: service,
        commandExecutor: RecordingCommandExecutor(result: .init(stdout: "", stderr: "", exitStatus: 0)),
        databaseDiscovery: EmptyDatabaseDiscovery(),
        originDiscovery: StaticOriginDiscovery(values: [origin]),
        configurationStore: StaticConfigurationStore()
    )
}

@MainActor
private func seedExactLifecyclePresentation(
    store: OpsStore,
    origin: CoordinatorOrigin
) throws -> (target: ExactUnassignedResource, repository: ProjectGroup, projectPath: String) {
    let repositoryURL = try selectionRepository(named: "exact-lifecycle")
    let projectPath = try XCTUnwrap(RepositoryIdentity(projectPath: repositoryURL.path)?.canonicalRoot)
    var server = try JSONDecoder().decode(
        ManagedServer.self,
        from: Data(#"{"id":"repo-server","name":"web","project":"\#(projectPath)","status":"stopped"}"#.utf8)
    )
    server.origin = origin
    let container = try exactUnassignedContainer(origin: origin)
    var inventory = Inventory.empty
    inventory.servers = [server]
    inventory.docker = DockerSummary(
        available: true,
        error: nil,
        statsError: nil,
        containers: [container],
        postgres: []
    )
    store.inventory = inventory
    markSourceLoaded(store, origin: origin, resourceCount: 2)
    let target = try XCTUnwrap(container.exactUnassignedResource)
    let repository = try XCTUnwrap(
        store.projectGroups.first { $0.isRepository && $0.projectPath == projectPath }
    )
    return (target, repository, projectPath)
}

private func exactUnassignedContainer(origin: CoordinatorOrigin) throws -> DockerContainer {
    var container = try JSONDecoder().decode(
        DockerContainer.self,
        from: Data(#"{"id":"immutable-copy-pg","name":"kosttracking-prod-copy-pg","status":"running","metadata_source":"normalized_store","attribution":{"reason_code":"ambiguous_control","explanation":"Observed without one authoritative repository binding","observed_by":["host-observer"],"controller":"docker-binding-1","host_resource_id":"docker:immutable-copy-pg","immutable_fingerprint":"container-fingerprint-1","control_binding_id":"docker-binding-1","ownership_fingerprint":"ownership-fingerprint-1","can_attach":true,"can_retire":true}}"#.utf8)
    )
    container.origin = origin
    return container
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
        withJSONObject: normalizedInventoryJSONObject(
            from: inventoryJSONObject(
            home: home,
            containers: containers,
            postgres: Array(containers.prefix(9))
            ),
            home: home
        ),
        options: [.prettyPrinted, .sortedKeys]
    )
    data.append(0x0A)
    return data
}

/// Test-only migration from the former presentation fixture shape into the
/// normalized v2 graph. Production intentionally has no equivalent fallback.
/// Keeping this adapter here lets the long-standing lifecycle/concurrency tests
/// exercise their original scenarios through the same authoritative contract
/// the app now consumes.
private func normalizedInventoryExecution(
    _ execution: CommandExecution,
    origin: CoordinatorOrigin,
    arguments: [String]
) throws -> CommandExecution {
    guard arguments.first == "inventory", execution.exitStatus == 0 else { return execution }
    let data = Data(execution.stdout.utf8)
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        return execution
    }
    if object["repositories"] != nil, object["resources"] != nil { return execution }
    let normalized = normalizedInventoryJSONObject(from: object, home: origin.home)
    let encoded = try JSONSerialization.data(withJSONObject: normalized, options: [.sortedKeys])
    return CommandExecution(
        stdout: String(decoding: encoded, as: UTF8.self),
        stderr: execution.stderr,
        exitStatus: execution.exitStatus,
        timedOut: execution.timedOut,
        cancelled: execution.cancelled,
        outputTruncated: execution.outputTruncated
    )
}

private func normalizedInventoryJSONObject(
    from legacy: [String: Any],
    home: String
) -> [String: Any] {
    let servers = legacy["servers"] as? [[String: Any]] ?? []
    let docker = legacy["docker"] as? [String: Any] ?? [:]
    let containers = docker["containers"] as? [[String: Any]] ?? []
    let postgres = legacy["postgres"] as? [[String: Any]]
        ?? docker["postgres"] as? [[String: Any]]
        ?? []
    let usageRows = legacy["project_usage"] as? [[String: Any]] ?? []
    let legacyLeases = legacy["leases"] as? [[String: Any]] ?? []
    let timestamp = "2026-07-15T12:00:00Z"

    var paths = Set<String>()
    func recordPath(_ value: Any?) {
        guard let value = value as? String, value.hasPrefix("/") else { return }
        paths.insert(URL(fileURLWithPath: value).standardizedFileURL.path)
    }
    servers.forEach { recordPath($0["project"]) }
    containers.forEach { recordPath($0["project"]) }
    postgres.forEach { recordPath($0["project"]) }
    usageRows.forEach { recordPath($0["project"]) }
    legacyLeases.forEach { recordPath($0["project"]) }

    let sortedPaths = paths.sorted()
    func repoID(for path: String) -> String {
        path == "/repo" ? "repo-1" : "repo-\(stableFixtureID(path))"
    }
    let usageByPath = Dictionary(
        uniqueKeysWithValues: usageRows.compactMap { row -> (String, [String: Any])? in
            guard let path = row["project"] as? String else { return nil }
            return (URL(fileURLWithPath: path).standardizedFileURL.path, row)
        }
    )
    let repositories: [[String: Any]] = sortedPaths.map { path in
        let displayName = (usageByPath[path]?["name"] as? String)
            ?? URL(fileURLWithPath: path).lastPathComponent
        return [
            "repo_id": repoID(for: path),
            "host_id": "host-fixture",
            "canonical_root": path,
            "display_name": displayName,
            "state": "active",
            "generation": 1,
            "installation_status": "active",
            "startup_fenced": false,
            "installation_generation": 1,
        ]
    }
    let sourceID = "source-\(stableFixtureID(home))"
    var memberships: [[String: Any]] = []
    var bindings: [[String: Any]] = []
    var serverDefinitions: [[String: Any]] = []
    var serverObservations: [[String: Any]] = []
    var dockerResources: [[String: Any]] = []
    var dockerObservations: [[String: Any]] = []
    var dockerPorts: [[String: Any]] = []
    var databaseBindings: [[String: Any]] = []
    var databaseObservations: [[String: Any]] = []
    var telemetry: [[String: Any]] = []
    var unassigned: [[String: Any]] = []

    func canonicalProject(_ row: [String: Any]) -> String? {
        guard let path = row["project"] as? String, path.hasPrefix("/") else { return nil }
        return URL(fileURLWithPath: path).standardizedFileURL.path
    }
    func lifecycle(_ status: Any?) -> String {
        let value = (status as? String ?? "unobserved").lowercased()
        if value.contains("unhealthy") { return "unhealthy" }
        if value.contains("up") || value == "running" || value == "starting" { return "running" }
        if value.contains("stop") || value.contains("exit") { return "stopped" }
        return value
    }
    func appendMembership(
        repoID: String,
        kind: String,
        resourceID: String,
        provenance: String
    ) {
        let bindingID = "binding-\(kind)-\(stableFixtureID(resourceID + repoID))"
        memberships.append([
            "membership_id": "membership-\(kind)-\(stableFixtureID(resourceID + repoID))",
            "repo_id": repoID,
            "resource_kind": kind,
            "host_resource_id": resourceID,
            "immutable_fingerprint": "fingerprint-\(stableFixtureID(resourceID))",
            "control_binding_id": bindingID,
        ])
        bindings.append([
            "binding_id": bindingID,
            "repo_id": repoID,
            "source_resource_id": resourceID,
            "resource_kind": kind,
            "resource_id": resourceID,
            "source_id": sourceID,
            "capability": "lifecycle",
            "provenance": provenance,
            "authority_state": "authoritative",
            "priority": 100,
            "generation": 1,
        ])
    }
    func appendUnassigned(
        row: [String: Any],
        kind: String,
        resourceID: String,
        displayName: String,
        running: Bool
    ) {
        let attribution = row["attribution"] as? [String: Any] ?? [:]
        let reasonCode = attribution["reason_code"] as? String ?? "missing_repo"
        unassigned.append([
            "unassigned_id": "unassigned-\(kind)-\(stableFixtureID(resourceID))",
            "resource_kind": kind,
            "resource_id": resourceID,
            "display_name": displayName,
            "reason_code": reasonCode,
            "explanation": attribution["explanation"] as? String
                ?? "The normalized fixture has no authoritative repository membership.",
            "observed_by": attribution["observed_by"] as? [String] ?? ["fixture-observer"],
            "controller": attribution["controller"] as? String ?? sourceID,
            "host_resource_id": attribution["host_resource_id"] as? String ?? resourceID,
            "immutable_fingerprint": attribution["immutable_fingerprint"] as? String
                ?? "fingerprint-\(stableFixtureID(resourceID))",
            "control_binding_id": attribution["control_binding_id"] as? String
                ?? "unassigned-binding-\(stableFixtureID(resourceID))",
            "ownership_fingerprint": attribution["ownership_fingerprint"] as? String
                ?? "ownership-\(stableFixtureID(resourceID))",
            "can_attach": attribution["can_attach"] as? Bool ?? true,
            "can_retire": attribution["can_retire"] as? Bool ?? true,
            "lifecycle_violation": attribution["lifecycle_violation"] as? Bool ?? running,
            "recommended_next_step": attribution["recommended_next_step"] as? String
                ?? "Attach this exact resource or retire it.",
        ])
    }

    for (index, row) in servers.enumerated() {
        let resourceID = row["id"] as? String ?? "server-fixture-\(index)"
        let name = row["name"] as? String ?? resourceID
        let currentLifecycle = lifecycle(row["status"])
        if let path = canonicalProject(row) {
            let repositoryID = repoID(for: path)
            serverDefinitions.append([
                "server_definition_id": resourceID,
                "repo_id": repositoryID,
                "name": name,
                "role": row["role"] as? String ?? "development",
                "cwd": row["cwd"] as? String ?? path,
                "health_url_template": row["health_url"] ?? NSNull(),
                "log_path": row["log_path"] ?? NSNull(),
                "definition_fingerprint": "server-definition-\(stableFixtureID(resourceID + path))",
                "generation": 1,
                "arguments": ["fixture-server", name],
            ])
            appendMembership(
                repoID: repositoryID,
                kind: "server",
                resourceID: resourceID,
                provenance: "normalized_fixture"
            )
            serverObservations.append([
                "server_definition_id": resourceID,
                "source_resource_id": resourceID,
                "lifecycle": currentLifecycle,
                "pid": row["pid"] ?? NSNull(),
                "listener_host": row["host"] as? String ?? "127.0.0.1",
                "listener_port": row["port"] ?? NSNull(),
                "listener_observable": 1,
                "health_classification": "fixture",
                "health_ok": ((row["health"] as? [String: Any])?["ok"] as? Bool).map { $0 ? 1 : 0 } ?? 1,
                "stopped_at": row["stopped_at"] ?? NSNull(),
                "stopped_reason": row["stopped_reason"] ?? NSNull(),
                "sampled_at": timestamp,
            ])
        } else {
            appendUnassigned(
                row: row,
                kind: "server",
                resourceID: resourceID,
                displayName: name,
                running: currentLifecycle == "running"
            )
        }
    }

    var containersByID: [String: [String: Any]] = [:]
    for (index, row) in (containers + postgres).enumerated() {
        let resourceID = row["id"] as? String ?? "docker-fixture-\(index)"
        if containersByID[resourceID] == nil { containersByID[resourceID] = row }
    }
    for (index, resourceID) in containersByID.keys.sorted().enumerated() {
        guard let row = containersByID[resourceID] else { continue }
        let name = row["name"] as? String ?? resourceID
        let currentLifecycle = lifecycle(row["status"])
        dockerResources.append([
            "docker_resource_id": resourceID,
            "engine_id": "engine-fixture",
            "full_container_id": resourceID,
            "current_name": name,
            "image": row["image"] ?? NSNull(),
            "created_at": timestamp,
            "updated_at": timestamp,
        ])
        dockerObservations.append([
            "docker_resource_id": resourceID,
            "lifecycle": currentLifecycle,
            "health": currentLifecycle == "running" ? "healthy" : "none",
            "restart_policy": "no",
            "sampled_at": timestamp,
        ])
        if let path = canonicalProject(row) {
            appendMembership(
                repoID: repoID(for: path),
                kind: "container",
                resourceID: resourceID,
                provenance: row["metadata_source"] as? String ?? "normalized_fixture"
            )
        } else {
            appendUnassigned(
                row: row,
                kind: "container",
                resourceID: resourceID,
                displayName: name,
                running: currentLifecycle == "running"
            )
        }
        if let portText = row["ports"] as? String,
           let hostPortText = portText.split(separator: ":").last?.split(separator: "-").first,
           let hostPort = Int(hostPortText)
        {
            dockerPorts.append([
                "docker_resource_id": resourceID,
                "ordinal": 0,
                "host_address": "0.0.0.0",
                "host_port": hostPort,
                "container_port": 5432,
                "protocol": "tcp",
            ])
        }
        var samples = row["stats_history"] as? [[String: Any]] ?? []
        if samples.isEmpty, let current = row["stats"] as? [String: Any] { samples = [current] }
        for (sampleIndex, sample) in samples.enumerated() {
            telemetry.append([
                "sample_id": "sample-\(index)-\(sampleIndex)",
                "host_resource_kind": "docker",
                "host_resource_id": resourceID,
                "sampled_at": sample["timestamp"] as? String
                    ?? String(format: "2026-07-15T12:%02d:%02dZ", (sampleIndex / 60) % 60, sampleIndex % 60),
                "cpu_percent": sample["cpu_percent"] ?? NSNull(),
                "memory_bytes": sample["memory_usage_bytes"] ?? NSNull(),
                "network_rx_bytes": sample["network_rx_bytes"] ?? NSNull(),
                "network_tx_bytes": sample["network_tx_bytes"] ?? NSNull(),
                "block_read_bytes": sample["block_read_bytes"] ?? NSNull(),
                "block_write_bytes": sample["block_write_bytes"] ?? NSNull(),
            ])
        }
    }

    var seenDatabaseIDs = Set<String>()
    for (index, row) in postgres.enumerated() {
        let dockerID = row["id"] as? String ?? "docker-fixture-\(index)"
        let databaseName = row["database"] as? String ?? "postgres"
        let bindingID = "database-\(stableFixtureID(dockerID + databaseName))"
        guard seenDatabaseIDs.insert(bindingID).inserted else { continue }
        let project = canonicalProject(row)
            ?? containersByID[dockerID].flatMap(canonicalProject)
        databaseBindings.append([
            "database_binding_id": bindingID,
            "docker_resource_id": dockerID,
            "repo_id": project.map(repoID(for:)) as Any? ?? NSNull(),
            "database_name": databaseName,
            "engine_kind": "postgresql",
            "created_at": timestamp,
            "updated_at": timestamp,
        ])
        let error = row["database_discovery_error"] as? String
        databaseObservations.append([
            "database_binding_id": bindingID,
            "docker_resource_id": dockerID,
            "available": error == nil ? 1 : 0,
            "size_bytes": row["database_size_bytes"] ?? NSNull(),
            "error_code": error == nil ? NSNull() : "fixture_error",
            "error_message": error as Any? ?? NSNull(),
            "sampled_at": timestamp,
            "observation_fingerprint": "database-observation-\(stableFixtureID(bindingID))",
        ])
    }

    let normalizedLeases: [[String: Any]] = legacyLeases.compactMap { row in
        guard let project = row["project"] as? String, project.hasPrefix("/"),
              let port = row["port"]
        else { return nil }
        return [
            "lease_id": row["id"] as? String ?? "lease-\(stableFixtureID(project))",
            "repo_id": repoID(for: URL(fileURLWithPath: project).standardizedFileURL.path),
            "server_definition_id": row["server_id"] ?? NSNull(),
            "source_id": sourceID,
            "port": port,
            "owner": row["agent"] ?? NSNull(),
            "agent": row["agent"] ?? NSNull(),
            "purpose": row["purpose"] ?? NSNull(),
            "status": row["status"] as? String ?? "active",
            "expires_at": row["expires_at_iso"] ?? NSNull(),
        ]
    }
    let portAssignments: [[String: Any]] = servers.compactMap { row in
        guard let project = canonicalProject(row),
              let name = row["name"] as? String,
              let port = row["port"]
        else { return nil }
        return [
            "assignment_id": "assignment-\(stableFixtureID(project + name))",
            "repo_id": repoID(for: project),
            "server_name": name,
            "port": port,
            "status": "active",
        ]
    }
    let available = docker["available"] as? Bool
    let engineState = available == false ? "unavailable" : "available"
    let lifecycleViolations = unassigned.filter { $0["lifecycle_violation"] as? Bool == true }
    return [
        "schema_version": 2,
        "store": [
            "database_generation": "fixture-generation",
            "state_revision": 1,
            "observation_revision": 1,
            "authority_mode": "sqlite",
            "migration_state": "complete",
            "updated_at": timestamp,
        ],
        "repositories": repositories,
        "coordinator_sources": [[
            "source_id": sourceID,
            "canonical_home": home,
            "effective_uid": 501,
            "status": "imported",
        ]],
        "docker_engines": [[
            "engine_id": "engine-fixture",
            "host_id": "host-fixture",
            "capability_state": engineState,
        ]],
        "memberships": memberships,
        "resources": [
            "servers": serverDefinitions,
            "docker": dockerResources,
            "docker_ports": dockerPorts,
            "databases": databaseBindings,
        ],
        "observations": [
            "servers": serverObservations,
            "docker": dockerObservations,
            "databases": databaseObservations,
            "telemetry": telemetry,
            "snapshots": [],
        ],
        "leases": normalizedLeases,
        "port_assignments": portAssignments,
        "backup_evidence": [],
        "database_backups": [],
        "database_restore_events": [],
        "events": [],
        "unassigned_resources": unassigned,
        "lifecycle_violations": lifecycleViolations,
        "control_bindings": bindings,
        "v1_compatibility": legacy,
    ]
}

private func stableFixtureID(_ value: String) -> String {
    var hash: UInt64 = 14_695_981_039_346_656_037
    for byte in value.utf8 {
        hash ^= UInt64(byte)
        hash &*= 1_099_511_628_211
    }
    return String(hash, radix: 16)
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
    let effectiveProject = project ?? "/repo"
    let projectJSON = ",\"project\":\"\(effectiveProject)\""
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
    let databaseFields = postgres ? #", "database":"app", "database_size_bytes":1024"# : ""
    let container = """
    {"id":"immutable-selection-container","name":"\(name)","image":"\(image)","status":"Up","project":"\(project)","metadata_source":"coordinator_sidecar"\(databaseFields)}
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

private func repositoryRemovalPlanJSON() -> String {
    #"{"schema_version":1,"kind":"repository_decommission","plan_id":"plan-remove-1","repo_id":"repo-1","repository_fingerprint":"repository-fingerprint-1","installation_generation":4,"fingerprint":"plan-fingerprint-1","created_at":"2026-07-14T12:00:00Z","actor":"tester","reason":"Removed from DevOps Board","canonical_root":"/repo","display_name":"Repo","retained_data":["repository_files","containers","volumes","databases","backups","audit_history"],"targets":[{"target_id":"server-target","kind":"server","host_resource_id":"server:immutable-1","immutable_fingerprint":"server-fingerprint-1","control_binding_id":"binding-1","display_name":"web","current_state":"running","policies":[{"policy_id":"policy-1","kind":"server_definition","immutable_fingerprint":"policy-fingerprint-1","disabled_value":"disabled"}],"allocations":[{"allocation_id":"lease-1","kind":"lease","immutable_fingerprint":"lease-fingerprint-1"}]}],"blockers":[]}"#
}

private func standaloneRetirementPlanJSON() -> String {
    #"{"schema_version":1,"kind":"standalone_resource_retirement","plan_id":"retire-plan-1","resource_id":"docker:immutable-copy-pg","fingerprint":"retire-fingerprint-1","created_at":"2026-07-14T12:00:00Z","actor":"tester","reason":"Retired from DevOps Board","retained_data":["containers","volumes","databases","backups","audit_history"],"targets":[{"target_id":"docker:immutable-copy-pg","kind":"container","host_resource_id":"docker:immutable-copy-pg","immutable_fingerprint":"container-fingerprint-1","control_binding_id":"docker-binding-1","display_name":"kosttracking-prod-copy-pg","current_state":"running","policies":[{"policy_id":"docker-policy-1","kind":"restart_policy","immutable_fingerprint":"restart-policy-fingerprint-1","disabled_value":"no"}],"allocations":[]}]}"#
}

private func emptyNormalizedInventoryExecution() -> CommandExecution {
    CommandExecution(
        stdout: #"{"schema_version":2,"coordinator_home":"/tmp/codex-home","state_path":"/tmp/codex-home/coordinator.sqlite3","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"available":true,"containers":[],"postgres":[]},"postgres":[],"backups":[],"project_usage":[]}"#,
        stderr: "",
        exitStatus: 0
    )
}

/// A hand-authored normalized graph used as the primary contract fixture.
/// Its poisoned v1 projection intentionally disagrees with every durable v2
/// identity so tests prove the Board cannot consult compatibility fields.
private func directV2GraphJSONObject(
    home: String,
    sourceHome: String? = nil,
    sourceStatus: String = "imported",
    dockerCapability: String = "available",
    databaseAvailable: Bool = true,
    databaseError: String? = nil,
    strongArtifactPath: String = "/backups/strong.dump"
) -> [String: Any] {
    let oldSample = "2026-07-15T11:00:00Z"
    let newSample = "2026-07-15T12:00:00Z"
    func backup(
        id: String,
        scope: String,
        verification: String,
        status: String,
        path: String,
        createdAt: String
    ) -> [String: Any] {
        [
            "database_backup_id": id,
            "database_binding_id": "database-binding-1",
            "docker_resource_id": "docker-resource-1",
            "repo_id": "repo-1",
            "source_id": "imported-source",
            "scope": scope,
            "source_container_id": "immutable-pg-container",
            "source_database_name": "app",
            "source_identity_fingerprint": "source-db-fingerprint",
            "artifact_path": path,
            "artifact_size_bytes": 4_096,
            "artifact_sha256": "artifact-sha-\(id)",
            "manifest_path": "\(path).manifest.json",
            "manifest_sha256": "manifest-sha-\(id)",
            "backup_format": "custom",
            "verification_status": verification,
            "verification_mode": verification == "strong" ? "test_restore" : "checksum",
            "created_at": createdAt,
            "verified_at": verification == "strong" ? createdAt as Any : NSNull(),
            "status": status,
            "last_restored_at": NSNull(),
            "restore_count": 0,
            "updated_at": createdAt,
        ]
    }
    return [
        "schema_version": 2,
        "store": [
            "database_generation": "direct-v2-generation",
            "state_revision": 9,
            "observation_revision": 11,
            "authority_mode": "sqlite",
            "migration_state": "complete",
            "updated_at": newSample,
        ],
        "repositories": [[
            "repo_id": "repo-1",
            "host_id": "host-1",
            "canonical_root": "/repo",
            "display_name": "Repo",
            "state": "active",
            "generation": 4,
            "installation_status": "active",
            "startup_fenced": false,
            "installation_generation": 4,
        ]],
        "coordinator_sources": [[
            "source_id": "imported-source",
            "canonical_home": sourceHome ?? home,
            "effective_uid": 501,
            "status": sourceStatus,
        ]],
        "docker_engines": [[
            "engine_id": "engine-1",
            "host_id": "host-1",
            "capability_state": dockerCapability,
        ]],
        "memberships": [
            [
                "membership_id": "server-membership-1",
                "repo_id": "repo-1",
                "resource_kind": "server",
                "host_resource_id": "server-definition-1",
                "immutable_fingerprint": "server-fingerprint",
                "control_binding_id": "server-binding-1",
            ],
            [
                "membership_id": "docker-membership-1",
                "repo_id": "repo-1",
                "resource_kind": "container",
                "host_resource_id": "docker-resource-1",
                "immutable_fingerprint": "docker-fingerprint",
                "control_binding_id": "docker-binding-1",
            ],
        ],
        "resources": [
            "servers": [[
                "server_definition_id": "server-definition-1",
                "repo_id": "repo-1",
                "name": "web",
                "role": "web",
                "cwd": "/repo",
                "health_url_template": "http://127.0.0.1:{port}/health",
                "log_path": "/tmp/web.log",
                "definition_fingerprint": "server-definition-fingerprint",
                "generation": 4,
                "arguments": ["npm", "run", "dev"],
            ]],
            "docker": [[
                "docker_resource_id": "docker-resource-1",
                "engine_id": "engine-1",
                "full_container_id": "immutable-pg-container",
                "current_name": "pg",
                "image": "postgres:17",
                "created_at": oldSample,
                "updated_at": newSample,
            ]],
            "docker_ports": [[
                "docker_resource_id": "docker-resource-1",
                "ordinal": 0,
                "host_address": "127.0.0.1",
                "host_port": 5_433,
                "container_port": 5_432,
                "protocol": "tcp",
            ]],
            "databases": [[
                "database_binding_id": "database-binding-1",
                "docker_resource_id": "docker-resource-1",
                "repo_id": "repo-1",
                "database_name": "app",
                "engine_kind": "postgresql",
                "created_at": oldSample,
                "updated_at": newSample,
            ]],
        ],
        "observations": [
            "servers": [[
                "server_definition_id": "server-definition-1",
                "source_resource_id": "legacy-server-row-77",
                "lifecycle": "stopped",
                "pid": NSNull(),
                "listener_host": NSNull(),
                "listener_port": NSNull(),
                "listener_observable": 1,
                "health_classification": "stopped",
                "health_ok": NSNull(),
                "stopped_at": newSample,
                "stopped_reason": "fixture",
                "sampled_at": newSample,
            ]],
            "docker": [[
                "docker_resource_id": "docker-resource-1",
                "lifecycle": "running",
                "health": "healthy",
                "restart_policy": "unless-stopped",
                "sampled_at": newSample,
            ]],
            "databases": [[
                "database_binding_id": "database-binding-1",
                "docker_resource_id": "docker-resource-1",
                "available": databaseAvailable ? 1 : 0,
                "size_bytes": databaseAvailable ? 8_192 as Any : NSNull(),
                "error_code": databaseError == nil ? NSNull() : "database_probe_failed",
                "error_message": databaseError as Any? ?? NSNull(),
                "sampled_at": newSample,
                "observation_fingerprint": "database-observation-fingerprint",
            ]],
            // Deliberately newest-first; projection must publish chronological
            // history and select the true newest sample as current stats.
            "telemetry": [
                [
                    "sample_id": "sample-new",
                    "host_resource_kind": "docker",
                    "host_resource_id": "docker-resource-1",
                    "sampled_at": newSample,
                    "cpu_percent": 22.0,
                    "memory_bytes": 2_048,
                ],
                [
                    "sample_id": "sample-old",
                    "host_resource_kind": "docker",
                    "host_resource_id": "docker-resource-1",
                    "sampled_at": oldSample,
                    "cpu_percent": 11.0,
                    "memory_bytes": 1_024,
                ],
            ],
            "snapshots": [],
        ],
        "leases": [
            [
                "lease_id": "lease-1",
                "repo_id": "repo-1",
                "server_definition_id": "server-definition-1",
                "source_id": "imported-source",
                "port": 4_317,
                "owner": "tester",
                "agent": "tester",
                "purpose": "web",
                "status": "active",
                "expires_at": "2099-01-01T00:00:00Z",
            ],
            [
                "lease_id": "lease-released",
                "repo_id": "repo-1",
                "server_definition_id": "server-definition-1",
                "source_id": "imported-source",
                "port": 4_318,
                "owner": "tester",
                "agent": "tester",
                "purpose": "old-web",
                "status": "released",
                "expires_at": NSNull(),
            ],
        ],
        "port_assignments": [[
            "assignment_id": "assignment-1",
            "repo_id": "repo-1",
            "server_name": "web",
            "port": 4_317,
            "status": "active",
        ]],
        "backup_evidence": [[
            "backup_id": "diagnostic-only",
            "repo_id": "repo-1",
            "source_id": "imported-source",
            "manifest_path": "/poison/evidence.manifest.json",
            "manifest_sha256": "diagnostic-sha",
            "verification_status": "strong",
            "created_at": newSample,
            "verified_at": newSample,
        ]],
        "database_backups": [
            backup(
                id: "backup-strong",
                scope: "database",
                verification: "strong",
                status: "available",
                path: strongArtifactPath,
                createdAt: "2026-07-15T10:00:00Z"
            ),
            backup(
                id: "backup-weak-newer",
                scope: "database",
                verification: "lightweight",
                status: "available",
                path: "/backups/weak.dump",
                createdAt: "2026-07-15T12:30:00Z"
            ),
            backup(
                id: "backup-cluster",
                scope: "cluster",
                verification: "strong",
                status: "available",
                path: "/backups/cluster.dump",
                createdAt: "2026-07-15T12:40:00Z"
            ),
            backup(
                id: "backup-missing",
                scope: "database",
                verification: "strong",
                status: "missing",
                path: "/backups/missing.dump",
                createdAt: "2026-07-15T12:50:00Z"
            ),
        ],
        "database_restore_events": [],
        "events": [],
        "unassigned_resources": [],
        "lifecycle_violations": [],
        "control_bindings": [
            [
                "binding_id": "server-binding-1",
                "repo_id": "repo-1",
                "source_resource_id": "legacy-server-row-77",
                "resource_kind": "server",
                "resource_id": "server-definition-1",
                "source_id": "imported-source",
                "capability": "lifecycle",
                "provenance": "imported_legacy",
                "authority_state": "authoritative",
                "priority": 100,
                "generation": 4,
            ],
            [
                "binding_id": "docker-binding-1",
                "repo_id": "repo-1",
                "source_resource_id": "legacy-docker-row-77",
                "resource_kind": "container",
                "resource_id": "docker-resource-1",
                "source_id": "imported-source",
                "capability": "lifecycle",
                "provenance": "imported_legacy",
                "authority_state": "authoritative",
                "priority": 100,
                "generation": 4,
            ],
        ],
        "v1_compatibility": [
            "coordinator_home": "/poison/legacy-home",
            "servers": [
                ["id": "poison-1", "name": "Nevod", "project": "Nevod"],
                ["id": "poison-2", "name": "Nevod", "project": "Nevod"],
                ["id": "poison-3", "name": "Nevod", "project": "Nevod"],
            ],
            "backups": [["path": "/poison/legacy.dump"]],
        ],
        "servers": [["id": "poison-top-level", "name": "Nevod", "project": "Nevod"]],
        "backups": [["path": "/poison/top-level.dump"]],
    ]
}

private func directV2Projection(
    from object: [String: Any],
    origin: CoordinatorOrigin,
    now: Date = Date()
) throws -> NormalizedBoardProjection {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return try JSONDecoder()
        .decode(NormalizedInventoryGraph.self, from: data)
        .boardProjection(origin: origin, now: now)
}

private func directV2InventoryExecution(
    home: String,
    sourceHome: String? = nil,
    sourceStatus: String = "imported",
    dockerCapability: String = "available",
    databaseAvailable: Bool = true,
    databaseError: String? = nil,
    strongArtifactPath: String = "/backups/strong.dump"
) throws -> CommandExecution {
    let data = try JSONSerialization.data(
        withJSONObject: directV2GraphJSONObject(
            home: home,
            sourceHome: sourceHome,
            sourceStatus: sourceStatus,
            dockerCapability: dockerCapability,
            databaseAvailable: databaseAvailable,
            databaseError: databaseError,
            strongArtifactPath: strongArtifactPath
        ),
        options: [.sortedKeys]
    )
    return CommandExecution(
        stdout: String(decoding: data, as: UTF8.self),
        stderr: "",
        exitStatus: 0
    )
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

private func serverProjectConflictInventoryExecution(home: String, project: String) -> CommandExecution {
    let json = """
    {"coordinator_home":"\(home)","state_path":"\(home)/state.json","urls":[],"servers":[{"id":"shared-web","name":"web","status":"running","project":"\(project)","host":"127.0.0.1","port":4317,"health":{"ok":true,"pid_alive":true}}],"leases":[],"recent_events":[],"docker":{"available":true,"containers":[],"postgres":[]},"postgres":[],"backups":[],"project_usage":[{"usage_key":"path:\(project)","project":"\(project)","project_key":"\(URL(fileURLWithPath: project).lastPathComponent)","name":"\(URL(fileURLWithPath: project).lastPathComponent)","server_ids":["shared-web"],"container_names":[],"server_count":1,"container_count":0,"process_count":1,"cpu_percent":0,"memory_bytes":0}]}
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

private actor NormalizedObservationCoordinatorService: CoordinatorServing {
    private var calls: [String] = []

    func observe(origin: CoordinatorOrigin, maxAgeSeconds: Double) async throws -> CommandExecution? {
        calls.append("observe:\(maxAgeSeconds)")
        return CommandExecution(
            stdout: #"{"schema_version":2,"status":"completed","observed":true}"#,
            stderr: "",
            exitStatus: 0
        )
    }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        calls.append(arguments.joined(separator: " "))
        return try normalizedInventoryExecution(CommandExecution(
            stdout: #"{"schema_version":2,"coordinator_home":"/tmp/account/.codex/agent-coordinator","state_path":"/tmp/account/.codex/agent-coordinator/coordinator.sqlite3","urls":[],"servers":[],"leases":[],"recent_events":[],"docker":{"available":true,"containers":[],"postgres":[{"id":"docker-resource-1","name":"postgres","database":"app","database_size_bytes":4096,"status":"running","metadata_source":"normalized_store"}]},"postgres":[{"id":"docker-resource-1","name":"postgres","database":"app","database_size_bytes":4096,"status":"running","metadata_source":"normalized_store"}],"backups":[],"project_usage":[]}"#,
            stderr: "",
            exitStatus: 0
        ), origin: origin, arguments: arguments)
    }

    func capturedCalls() -> [String] { calls }
}

private actor FailingObservationCoordinatorService: CoordinatorServing {
    private var calls: [String] = []

    func observe(origin: CoordinatorOrigin, maxAgeSeconds: Double) async throws -> CommandExecution? {
        calls.append("observe:\(maxAgeSeconds)")
        return CommandExecution(
            stdout: "",
            stderr: "injected bounded Docker observation failure",
            exitStatus: 1
        )
    }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        calls.append(arguments.joined(separator: " "))
        return try directV2InventoryExecution(home: origin.home)
    }

    func capturedCalls() -> [String] { calls }
}

private actor ExactLifecycleCoordinatorService: CoordinatorServing {
    private var results: [CommandExecution]
    private var calls: [(CoordinatorOrigin, [String])] = []

    init(results: [CommandExecution]) {
        self.results = results
    }

    func requestProjectRoot() async throws -> String? {
        "/workflow/repo"
    }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        calls.append((origin, arguments))
        guard !results.isEmpty else { throw MockFailure.offline }
        return try normalizedInventoryExecution(results.removeFirst(), origin: origin, arguments: arguments)
    }

    func capturedCalls() -> [(CoordinatorOrigin, [String])] { calls }
}

private struct MustNotRunDatabaseDiscovery: DatabaseDiscovering {
    func discover(origin: CoordinatorOrigin, container: String, containerID: String?) async throws -> [DiscoveredDatabase] {
        throw RuntimeError("normalized inventory must not rediscover databases in the Board")
    }
}

private actor OriginSequencedCoordinatorService: CoordinatorServing {
    private var results: [String: [Result<CommandExecution, MockFailure>]]
    private var calls: [(CoordinatorOrigin, [String])] = []

    init(results: [String: [Result<CommandExecution, MockFailure>]]) { self.results = results }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        calls.append((origin, arguments))
        guard var queue = results[origin.id], !queue.isEmpty else { throw MockFailure.offline }
        let result = queue.removeFirst()
        results[origin.id] = queue
        return try normalizedInventoryExecution(try result.get(), origin: origin, arguments: arguments)
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
        return try normalizedInventoryExecution(result, origin: origin, arguments: arguments)
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
        return try normalizedInventoryExecution(result, origin: origin, arguments: arguments)
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
        return try normalizedInventoryExecution(
            try outcomes.removeFirst().get(),
            origin: origin,
            arguments: arguments
        )
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
    private var projectRoots: [String] = []
    private let authority: BackupExecutionAuthority

    init(
        results: [CommandExecution],
        authority: BackupExecutionAuthority = .direct
    ) {
        self.results = results
        self.authority = authority
    }

    func executionAuthority(
        origin: CoordinatorOrigin?,
        projectRoot: String
    ) async throws -> BackupExecutionAuthority {
        authority
    }

    func execute(
        origin: CoordinatorOrigin?,
        projectRoot: String,
        arguments: [String]
    ) async throws -> CommandExecution {
        self.arguments.append(arguments)
        projectRoots.append(projectRoot)
        guard !results.isEmpty else { throw MockFailure.offline }
        return results.removeFirst()
    }

    func capturedArguments() -> [[String]] { arguments }
    func capturedProjectRoots() -> [String] { projectRoots }
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
