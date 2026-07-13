import Foundation
import XCTest
@testable import DevOpsBoard

final class RepositoryCatalogTests: XCTestCase {
    private let account = CoordinatorOrigin(label: "Codex", home: "/tmp/repository-catalog/account")
    private let chatGPT = CoordinatorOrigin(label: "Parall ChatGPT", home: "/tmp/repository-catalog/chatgpt")
    private let codexTT = CoordinatorOrigin(label: "Parall Codex", home: "/tmp/repository-catalog/codex")
    private var repositoryFixtureRoots: [URL] = []

    override func tearDownWithError() throws {
        for root in repositoryFixtureRoots { try? FileManager.default.removeItem(at: root) }
        repositoryFixtureRoots.removeAll()
        try super.tearDownWithError()
    }

    func testThreeLiveShapedNevodSourcesProduceOneRepositoryAndOnePhysicalUsageTotal() throws {
        let project = try repositoryPath(named: "Nevod")
        let containerSpecs: [(String, String, Double, Double)] = [
            ("0845bd293e8d", "nevod-telegram-worker", 0.6, 100_000_000),
            ("3948d267e07e", "nevod-postgres", 2.0, 3_600_000_000),
        ]
        let sources = try [
            source(
                origin: account,
                containers: containerSpecs.map {
                    try dockerContainer(
                        origin: account,
                        id: $0.0,
                        name: $0.1,
                        project: project,
                        cpu: $0.2,
                        memory: $0.3,
                        sampledAt: 1
                    )
                },
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "Nevod",
                    containerNames: containerSpecs.map(\.1),
                    cpu: 2.6,
                    memory: 3_700_000_000
                )
            ),
            source(
                origin: chatGPT,
                containers: containerSpecs.map {
                    try dockerContainer(
                        origin: chatGPT,
                        id: $0.0,
                        name: $0.1,
                        project: project,
                        cpu: $0.2,
                        memory: $0.3,
                        sampledAt: 2
                    )
                },
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(project)",
                    project: project,
                    name: "Nevod (ChatGPT)",
                    containerNames: containerSpecs.map(\.1),
                    cpu: 2.6,
                    memory: 3_700_000_000
                )
            ),
            source(
                origin: codexTT,
                servers: [
                    try server(origin: codexTT, id: "nevod-web", name: "web", project: project, port: 3000, status: "stopped"),
                    try server(origin: codexTT, id: "nevod-worker", name: "worker", project: project, port: 3001, status: "stopped"),
                ],
                containers: containerSpecs.map {
                    try dockerContainer(
                        origin: codexTT,
                        id: $0.0,
                        name: $0.1,
                        project: project,
                        cpu: $0.2,
                        memory: $0.3,
                        sampledAt: 3
                    )
                },
                usage: usage(
                    origin: codexTT,
                    key: "path:\(project)",
                    project: project,
                    name: "Nevod local",
                    serverIDs: ["nevod-web", "nevod-worker"],
                    containerNames: containerSpecs.map(\.1),
                    cpu: 2.6,
                    memory: 3_700_000_000
                )
            ),
        ]

        let catalog = RepositoryCatalog.build(from: sources)
        let repository = try XCTUnwrap(catalog.repositories.first)

        XCTAssertEqual(catalog.repositories.count, 1)
        XCTAssertEqual(repository.identity.canonicalRoot, project)
        XCTAssertEqual(repository.displayName, "Nevod")
        XCTAssertTrue(repository.observedLabels.contains("Nevod"))
        XCTAssertTrue(repository.observedLabels.contains("Nevod (ChatGPT)"))
        XCTAssertTrue(repository.observedLabels.contains("Nevod local"))
        XCTAssertEqual(repository.sourceObservations.count, 3)
        XCTAssertEqual(repository.servers.count, 2)
        XCTAssertEqual(repository.docker.count, 2)
        XCTAssertEqual(repository.usage.serverCount, 2)
        XCTAssertEqual(repository.usage.containerCount, 2)
        XCTAssertEqual(repository.usage.cpuPercent, 2.6, accuracy: 0.0001)
        XCTAssertEqual(repository.usage.memoryBytes, 3_700_000_000, accuracy: 0.1)
        XCTAssertEqual(repository.controlOrigin, codexTT)
        XCTAssertFalse(repository.projectActionsBlocked)
        XCTAssertTrue(repository.serverConflicts.isEmpty)

        for resource in repository.docker {
            XCTAssertTrue(resource.identity.isImmutable)
            XCTAssertEqual(resource.observations.count, 3)
            XCTAssertEqual(resource.sourceOrigins, Set([account, chatGPT, codexTT]))
            XCTAssertEqual(Set(resource.sourceIdentities.map(\.origin)), Set([account, chatGPT, codexTT]))
        }
        XCTAssertTrue(repository.servers.allSatisfy { $0.sourceOrigins == Set([codexTT]) })

        var presentation = Inventory(
            coordinatorHome: sources.map { $0.origin.home }.joined(separator: ", "),
            statePath: nil,
            project: nil,
            urls: [],
            servers: sources.flatMap { $0.inventory.servers },
            leases: [],
            recentEvents: [],
            docker: DockerSummary(
                available: true,
                error: nil,
                statsError: nil,
                containers: sources.flatMap { $0.inventory.docker.containers },
                postgres: []
            ),
            postgres: [],
            backups: [],
            projectUsage: sources.flatMap { $0.inventory.projectUsage }
        )
        presentation.origin = account
        let groups = makeProjectGroups(from: catalog, inventory: presentation)
        let visibleRepository = try XCTUnwrap(groups.first)
        XCTAssertEqual(groups.count, 1, "the actual Board adapter must not recreate source-scoped project shells")
        XCTAssertEqual(visibleRepository.id, "path:\(project)")
        XCTAssertEqual(visibleRepository.servers.count, 2)
        XCTAssertEqual(visibleRepository.containers.count, 1)
        XCTAssertEqual(visibleRepository.databases.count, 0)
        XCTAssertEqual(visibleRepository.usage?.containerCount, 2)
        XCTAssertEqual(try XCTUnwrap(visibleRepository.usage?.memoryBytes), 3_700_000_000, accuracy: 0.1)
    }

    func testSameDisplayNameWithDifferentCanonicalPathsRemainsTwoRepositories() throws {
        let left = try repositoryPath(named: "Nevod")
        let right = try repositoryPath(named: "Nevod")
        let catalog = RepositoryCatalog.build(from: [
            source(origin: account, usage: usage(origin: account, key: "path:\(left)", project: left, name: "Nevod")),
            source(origin: chatGPT, usage: usage(origin: chatGPT, key: "path:\(right)", project: right, name: "Nevod")),
        ])

        XCTAssertEqual(catalog.repositories.count, 2)
        XCTAssertEqual(Set(catalog.repositories.map(\.displayName)), ["Nevod"])
        XCTAssertEqual(Set(catalog.repositories.map(\.identity.canonicalRoot)).count, 2)
    }

    func testRepositoryIdentityCanonicalizesARealPathAlias() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("repository-catalog-\(UUID().uuidString)", isDirectory: true)
        let repository = root.appendingPathComponent("Nevod", isDirectory: true)
        let alias = root.appendingPathComponent("Nevod-alias", isDirectory: true)
        try FileManager.default.createDirectory(at: repository, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: repository.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: repository)
        defer { try? FileManager.default.removeItem(at: root) }

        XCTAssertEqual(
            RepositoryIdentity(projectPath: repository.path),
            RepositoryIdentity(projectPath: alias.path)
        )
    }

    func testRepositoryIdentityWalksFromNestedDirectoryToVerifiedGitRoot() throws {
        let project = try repositoryPath(named: "nested-root")
        let nested = URL(fileURLWithPath: project, isDirectory: true)
            .appendingPathComponent("apps/web/src", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        XCTAssertEqual(
            try XCTUnwrap(RepositoryIdentity(projectPath: nested.path)).canonicalRoot,
            project
        )
    }

    func testMissingAndNonGitPathEvidenceNeverCreatesActiveRepositories() throws {
        let fixtureRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("repository-catalog-unverified-\(UUID().uuidString)", isDirectory: true)
        let nonGit = fixtureRoot.appendingPathComponent("ordinary-directory", isDirectory: true)
        let missing = fixtureRoot.appendingPathComponent("deleted-repository", isDirectory: true)
        try FileManager.default.createDirectory(at: nonGit, withIntermediateDirectories: true)
        repositoryFixtureRoots.append(fixtureRoot)
        let stoppedServer = try server(
            origin: account,
            id: "historical-web",
            name: "web",
            project: nonGit.path,
            port: 3288,
            status: "stopped"
        )
        let historicalContainer = try dockerContainer(
            origin: chatGPT,
            id: "historical-container-id",
            name: "historical-worker",
            project: missing.path,
            cpu: 0,
            memory: 0,
            sampledAt: 1
        )

        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [stoppedServer],
                usage: usage(
                    origin: account,
                    key: "path:\(nonGit.path)",
                    project: nonGit.path,
                    name: "ordinary",
                    serverIDs: ["historical-web"]
                )
            ),
            source(
                origin: chatGPT,
                containers: [historicalContainer],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(missing.path)",
                    project: missing.path,
                    name: "deleted",
                    containerNames: ["historical-worker"]
                )
            ),
        ])

        XCTAssertNil(RepositoryIdentity(projectPath: nonGit.path))
        XCTAssertNil(RepositoryIdentity(projectPath: missing.path))
        XCTAssertTrue(catalog.repositories.isEmpty)
        XCTAssertEqual(catalog.unassigned.servers.map { $0.server.name }, ["web"])
        XCTAssertEqual(catalog.unassigned.docker.compactMap { $0.representative.name }, ["historical-worker"])
        XCTAssertEqual(Set(catalog.unassigned.usageObservations.compactMap(\.project)), Set([nonGit.path, missing.path]))
        let groups = makeProjectGroups(from: catalog, inventory: .empty)
        XCTAssertEqual(groups.map(\.id), [unassignedProjectGroupID])
        XCTAssertEqual(groups.first?.unassignedEvidenceCount, 2)
        XCTAssertEqual(groups.first?.servers.count, 1)
        XCTAssertEqual(groups.first?.containers.count, 1)
    }

    func testNameOnlyRowsAndRepeatedContainerBecomeOneUnassignedAggregate() throws {
        let containerID = "a1c0ffee00000000000000000000000000000000000000000000000000000000"
        let origins = [account, chatGPT, codexTT]
        let sources = try origins.map { origin in
            source(
                origin: origin,
                containers: [
                    try dockerContainer(
                        origin: origin,
                        id: containerID,
                        name: "aicursegmailcheck-postgres-dev",
                        project: nil,
                        cpu: 0,
                        memory: 512_000_000,
                        sampledAt: 1
                    )
                ],
                usage: usage(
                    origin: origin,
                    key: "name:aicursegmailcheck",
                    project: nil,
                    name: "aicursegmailcheck",
                    containerNames: ["aicursegmailcheck-postgres-dev"]
                )
            )
        }

        let catalog = RepositoryCatalog.build(from: sources)

        XCTAssertTrue(catalog.repositories.isEmpty)
        XCTAssertEqual(catalog.unassigned.docker.count, 1)
        XCTAssertEqual(catalog.unassigned.docker.first?.observations.count, 3)
        XCTAssertEqual(catalog.unassigned.usageObservations.count, 3)
    }

    func testDockerOnlyRepositoryUsesItsSingleProvenSourceAsProjectController() throws {
        let project = try repositoryPath(named: "docker-only")
        let container = try dockerContainer(
            origin: account,
            id: "d0c0a1100000",
            name: "docker-only-postgres",
            project: project,
            cpu: 1.5,
            memory: 256_000_000,
            sampledAt: 1
        )
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                containers: [container],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "docker-only",
                    containerNames: ["docker-only-postgres"],
                    cpu: 1.5,
                    memory: 256_000_000
                )
            )
        ])

        let repository = try XCTUnwrap(catalog.repositories.first)
        let resource = try XCTUnwrap(repository.docker.first)
        XCTAssertEqual(resource.sourceIdentities.map(\.origin), [account])
        XCTAssertEqual(repository.controlOrigin, account)
        XCTAssertFalse(repository.projectActionsBlocked)
        XCTAssertEqual(repository.usage.cpuPercent, 1.5, accuracy: 0.0001)
        XCTAssertEqual(repository.usage.memoryBytes, 256_000_000, accuracy: 0.1)
    }

    func testDistinctSimultaneouslyActiveServersBecomeOneBlockedConflict() throws {
        let project = try repositoryPath(named: "Nevod")
        let left = try server(
            origin: account,
            id: "left-web",
            name: "web",
            project: project,
            port: 3000,
            status: "running",
            pid: 111
        )
        let right = try server(
            origin: chatGPT,
            id: "right-web",
            name: "web",
            project: project,
            port: 3100,
            status: "running",
            pid: 222
        )
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [left],
                usage: usage(origin: account, key: "path:\(project)", project: project, name: "Nevod", serverIDs: ["left-web"])
            ),
            source(
                origin: chatGPT,
                servers: [right],
                usage: usage(origin: chatGPT, key: "path:\(project)", project: project, name: "Nevod", serverIDs: ["right-web"])
            ),
        ])

        let repository = try XCTUnwrap(catalog.repositories.first)
        let service = try XCTUnwrap(repository.servers.first)
        let conflict = try XCTUnwrap(service.conflict)

        XCTAssertEqual(repository.servers.count, 1, "one logical service must not become duplicate project rows")
        XCTAssertEqual(service.observations.count, 2)
        XCTAssertEqual(Set(conflict.activeSourceIdentities.map(\.origin)), Set([account, chatGPT]))
        XCTAssertTrue(service.isActionBlocked)
        XCTAssertNil(repository.controlOrigin)
        XCTAssertTrue(repository.projectActionsBlocked)
    }

    func testDuplicateServerRowsWithinOneSourceRemainOneLogicalService() throws {
        let project = try repositoryPath(named: "duplicate-state-row")
        let web = try server(
            origin: account,
            id: "duplicate-web",
            name: "web",
            project: project,
            port: 3292,
            status: "running",
            pid: 3292
        )
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [web, web],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "duplicate-state-row",
                    serverIDs: ["duplicate-web"]
                )
            )
        ])

        let repository = try XCTUnwrap(catalog.repositories.first)
        XCTAssertEqual(catalog.repositories.count, 1)
        XCTAssertEqual(repository.servers.count, 1)
        XCTAssertEqual(repository.servers.first?.identity.serviceKey, "web")
        XCTAssertEqual(repository.controlOrigin, account)
        XCTAssertTrue(catalog.unassigned.servers.isEmpty)
    }

    func testUsageAndExplicitResourcePathContradictionsStayUnassignedAndBlockEveryCandidate() throws {
        let usageProject = try repositoryPath(named: "usage-owner")
        let explicitProject = try repositoryPath(named: "explicit-owner")
        let conflictedServer = try server(
            origin: account,
            id: "contradicted-web",
            name: "web",
            project: explicitProject,
            port: 3290,
            status: "stopped"
        )
        let conflictedContainer = try dockerContainer(
            origin: account,
            id: "contradicted-container-id",
            name: "contradicted-worker",
            project: explicitProject,
            cpu: 7,
            memory: 900,
            sampledAt: 1
        )
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [conflictedServer],
                containers: [conflictedContainer],
                usage: usage(
                    origin: account,
                    key: "path:\(usageProject)",
                    project: usageProject,
                    name: "usage-owner",
                    serverIDs: ["contradicted-web"],
                    containerNames: ["contradicted-worker"]
                )
            )
        ])

        XCTAssertEqual(Set(catalog.repositories.map(\.identity.canonicalRoot)), Set([usageProject, explicitProject]))
        XCTAssertEqual(catalog.unassigned.servers.count, 1)
        XCTAssertEqual(catalog.unassigned.docker.count, 1)
        XCTAssertNotNil(catalog.unassigned.servers.first?.server.ownershipError)
        XCTAssertNotNil(catalog.unassigned.docker.first?.membershipError)
        for repository in catalog.repositories {
            XCTAssertTrue(repository.servers.isEmpty)
            XCTAssertTrue(repository.docker.isEmpty)
            XCTAssertEqual(repository.serverMembershipConflicts.count, 1)
            XCTAssertEqual(repository.dockerMembershipConflicts.count, 1)
            XCTAssertEqual(repository.usage.serverCount, 0)
            XCTAssertEqual(repository.usage.containerCount, 0)
            XCTAssertTrue(repository.projectActionsBlocked)
        }
        XCTAssertEqual(repositoryCatalogConflictHealthSignals(catalog).count, 2)

        let groups = makeProjectGroups(from: catalog, inventory: .empty)
        XCTAssertEqual(groups.filter(\.isRepository).count, 2)
        let unassigned = try XCTUnwrap(groups.first { !$0.isRepository })
        XCTAssertEqual(unassigned.servers.count, 1)
        XCTAssertEqual(unassigned.containers.count, 1)
        XCTAssertNil(unassigned.servers.first?.resourceIdentity)
        XCTAssertNil(unassigned.containers.first?.resourceIdentity)
    }

    func testRootAndNestedResourceClaimsResolveToOneRepositoryWithoutFalseConflict() throws {
        let project = try repositoryPath(named: "nested-membership")
        let nested = URL(fileURLWithPath: project, isDirectory: true)
            .appendingPathComponent("packages/web", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let nestedServer = try server(
            origin: account,
            id: "nested-web",
            name: "web",
            project: nested.path,
            port: 3291,
            status: "stopped"
        )
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [nestedServer],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "nested-membership",
                    serverIDs: ["nested-web"]
                )
            )
        ])

        let repository = try XCTUnwrap(catalog.repositories.first)
        XCTAssertEqual(catalog.repositories.count, 1)
        XCTAssertEqual(repository.identity.canonicalRoot, project)
        XCTAssertEqual(repository.servers.count, 1)
        XCTAssertTrue(repository.serverMembershipConflicts.isEmpty)
        XCTAssertEqual(repository.controlOrigin, account)
    }

    func testSamePhysicalAndStoppedServicesCollapseWithoutLosingRoutingProvenance() throws {
        let project = try repositoryPath(named: "shared")
        let leftWeb = try server(
            origin: account,
            id: "left-web",
            name: "web",
            project: project,
            port: 3000,
            status: "running",
            pid: 900,
            processCPU: 12,
            processMemory: 1_000,
            sampledAt: "2026-07-13T10:00:00Z"
        )
        let rightWeb = try server(
            origin: chatGPT,
            id: "right-web",
            name: "web",
            project: project,
            port: 3000,
            status: "running",
            pid: 900,
            processCPU: 13,
            processMemory: 1_100,
            sampledAt: "2026-07-13T10:00:01Z"
        )
        let leftWorker = try server(origin: account, id: "left-worker", name: "worker", project: project, port: 3001, status: "stopped")
        let rightWorker = try server(origin: chatGPT, id: "right-worker", name: "worker", project: project, port: 3001, status: "stopped")
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [leftWeb, leftWorker],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "shared",
                    serverIDs: ["left-web", "left-worker"],
                    cpu: 12,
                    memory: 1_000
                )
            ),
            source(
                origin: chatGPT,
                servers: [rightWeb, rightWorker],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(project)",
                    project: project,
                    name: "Shared local",
                    serverIDs: ["right-web", "right-worker"],
                    cpu: 13,
                    memory: 1_100
                )
            ),
        ])

        let repository = try XCTUnwrap(catalog.repositories.first)
        XCTAssertEqual(repository.servers.count, 2)
        XCTAssertTrue(repository.servers.allSatisfy { $0.observations.count == 2 })
        XCTAssertTrue(
            repository.servers.allSatisfy(\.isActionBlocked),
            "two state homes retaining one definition must not make an arbitrary resource controller actionable"
        )
        XCTAssertEqual(
            Set(repository.servers.flatMap(\.sourceIdentities).map(\.origin)),
            Set([account, chatGPT])
        )
        XCTAssertNil(
            repository.controlOrigin,
            "two complete source controllers are ambiguous, so repository actions must not guess"
        )
        XCTAssertEqual(repository.usage.processCount, 1)
        XCTAssertEqual(repository.usage.cpuPercent, 13, accuracy: 0.0001)
        XCTAssertEqual(repository.usage.memoryBytes, 1_100, accuracy: 0.1)
    }

    func testOneActiveSourceWinsOverStaleStoppedDefinitionWithoutSplittingRepository() throws {
        let project = try repositoryPath(named: "shared")
        let active = try server(
            origin: account,
            id: "account-web",
            name: "web",
            project: project,
            port: 3000,
            status: "running",
            pid: 901
        )
        let stale = try server(
            origin: chatGPT,
            id: "legacy-web",
            name: "web",
            project: project,
            port: 3000,
            status: "stopped"
        )
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [active],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "shared",
                    serverIDs: ["account-web"]
                )
            ),
            source(
                origin: chatGPT,
                servers: [stale],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(project)",
                    project: project,
                    name: "shared legacy",
                    serverIDs: ["legacy-web"]
                )
            ),
        ])

        let repository = try XCTUnwrap(catalog.repositories.first)
        let service = try XCTUnwrap(repository.servers.first)
        XCTAssertEqual(catalog.repositories.count, 1)
        XCTAssertEqual(service.observations.count, 2)
        XCTAssertNil(service.conflict)
        XCTAssertEqual(service.actionOrigin, account)
        XCTAssertFalse(service.isActionBlocked)
        XCTAssertEqual(repository.controlOrigin, account)
    }

    func testUniqueWholeRepositoryControllerSurvivesPartialStoppedLegacyOverlap() throws {
        let project = try repositoryPath(named: "shared")
        let accountWeb = try server(origin: account, id: "account-web", name: "web", project: project, port: 3000, status: "stopped")
        let accountWorker = try server(origin: account, id: "account-worker", name: "worker", project: project, port: 3001, status: "stopped")
        let legacyWeb = try server(origin: chatGPT, id: "legacy-web", name: "web", project: project, port: 3000, status: "stopped")
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [accountWeb, accountWorker],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "shared",
                    serverIDs: ["account-web", "account-worker"]
                )
            ),
            source(
                origin: chatGPT,
                servers: [legacyWeb],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(project)",
                    project: project,
                    name: "shared legacy",
                    serverIDs: ["legacy-web"]
                )
            ),
        ])

        let repository = try XCTUnwrap(catalog.repositories.first)
        let web = try XCTUnwrap(repository.servers.first { $0.identity.serviceKey == "web" })
        let worker = try XCTUnwrap(repository.servers.first { $0.identity.serviceKey == "worker" })
        XCTAssertNil(web.actionOrigin, "the duplicated stopped web definition remains unsafe as a resource action")
        XCTAssertEqual(Set(web.controlCandidates), Set([account, chatGPT]))
        XCTAssertEqual(worker.actionOrigin, account)
        XCTAssertEqual(repository.controlOrigin, account, "only the account source covers the complete repository runtime")
        XCTAssertFalse(repository.projectActionsBlocked)
    }

    func testDatabaseObservedWithoutProjectIsNotDuplicatedIntoUnassignedWhenContainerMembershipIsKnown() throws {
        let project = try repositoryPath(named: "database-owner")
        let database = try dockerContainer(
            origin: account,
            id: "database-container-id",
            name: "database-owner-postgres",
            project: nil,
            cpu: 0,
            memory: 512_000_000,
            sampledAt: 1
        )
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                containers: [database],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "database-owner",
                    containerNames: ["database-owner-postgres"]
                )
            )
        ])
        var inventory = catalogInventory(
            origin: account,
            containers: [database],
            databases: [database],
            usage: usage(
                origin: account,
                key: "path:\(project)",
                project: project,
                name: "database-owner",
                containerNames: ["database-owner-postgres"]
            )
        )
        inventory.postgres[0].database = "appdb"

        let groups = makeProjectGroups(from: catalog, inventory: inventory)

        XCTAssertEqual(groups.filter(\.isRepository).count, 1)
        XCTAssertEqual(groups.first(where: \.isRepository)?.databases.count, 1)
        XCTAssertFalse(groups.contains { $0.kind == .unassigned })
    }

    func testOwnedAndUnownedObservationsOfOneContainerResolveToRepositoryOnce() throws {
        let project = try repositoryPath(named: "owned")
        let containerID = "shared-owned-container-id"
        let unowned = try dockerContainer(
            origin: account,
            id: containerID,
            name: "owned-worker",
            project: nil,
            cpu: 3,
            memory: 100,
            sampledAt: 3
        )
        var owned = try dockerContainer(
            origin: chatGPT,
            id: containerID,
            name: "owned-worker",
            project: project,
            cpu: 2,
            memory: 100,
            sampledAt: 2
        )
        owned.metadataSource = "coordinator_sidecar"
        let sources = [
            source(
                origin: account,
                containers: [unowned],
                usage: usage(
                    origin: account,
                    key: "name:owned-worker",
                    project: nil,
                    name: "owned-worker",
                    containerNames: ["owned-worker"]
                )
            ),
            source(
                origin: chatGPT,
                containers: [owned],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(project)",
                    project: project,
                    name: "owned",
                    containerNames: ["owned-worker"]
                )
            ),
        ]

        let catalog = RepositoryCatalog.build(from: sources)
        let repository = try XCTUnwrap(catalog.repositories.first)
        XCTAssertEqual(catalog.repositories.count, 1)
        XCTAssertEqual(repository.docker.count, 1)
        XCTAssertEqual(repository.docker.first?.observations.count, 2)
        XCTAssertTrue(catalog.unassigned.docker.isEmpty)

        var presentation = sources[1].inventory
        presentation.docker.containers = [owned]
        presentation.projectUsage = sources.flatMap { $0.inventory.projectUsage }
        let groups = makeProjectGroups(from: catalog, inventory: presentation)
        let visible = try XCTUnwrap(groups.first)
        let visibleContainer = try XCTUnwrap(visible.containers.first)
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(visibleContainer.origin, chatGPT)
        XCTAssertEqual(visibleContainer.stableID, owned.stableID)
        XCTAssertEqual(visibleContainer.resourceIdentity?.origin, chatGPT)
        XCTAssertEqual(Set(visibleContainer.ownershipCandidates), Set([chatGPT]))
        XCTAssertEqual(Set(visibleContainer.observationOrigins), Set([account, chatGPT]))
    }

    func testConflictingRepositoryClaimsKeepOnePhysicalContainerUnassignedAndBlocked() throws {
        let containerID = "cross-project-container-id"
        let leftProject = try repositoryPath(named: "left")
        let rightProject = try repositoryPath(named: "right")
        var left = try dockerContainer(
            origin: account,
            id: containerID,
            name: "shared-worker",
            project: leftProject,
            cpu: 1,
            memory: 100,
            sampledAt: 1
        )
        left.metadataSource = "coordinator_sidecar"
        var right = try dockerContainer(
            origin: chatGPT,
            id: containerID,
            name: "shared-worker",
            project: rightProject,
            cpu: 2,
            memory: 100,
            sampledAt: 2
        )
        right.metadataSource = "coordinator_sidecar"
        let sources = [
            source(
                origin: account,
                containers: [left],
                usage: usage(
                    origin: account,
                    key: "path:\(leftProject)",
                    project: leftProject,
                    name: "left",
                    containerNames: ["shared-worker"]
                )
            ),
            source(
                origin: chatGPT,
                containers: [right],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(rightProject)",
                    project: rightProject,
                    name: "right",
                    containerNames: ["shared-worker"]
                )
            ),
        ]

        let catalog = RepositoryCatalog.build(from: sources)
        XCTAssertEqual(catalog.repositories.count, 2)
        XCTAssertTrue(catalog.repositories.allSatisfy { $0.docker.isEmpty })
        let conflict = try XCTUnwrap(catalog.unassigned.docker.first)
        XCTAssertEqual(catalog.unassigned.docker.count, 1)
        XCTAssertEqual(Set(conflict.repositoryCandidates), Set([RepositoryIdentity(projectPath: leftProject)!, RepositoryIdentity(projectPath: rightProject)!]))
        XCTAssertNotNil(conflict.membershipError)

        var presentation = sources[0].inventory
        presentation.docker.containers = [left]
        presentation.projectUsage = sources.flatMap { $0.inventory.projectUsage }
        let groups = makeProjectGroups(from: catalog, inventory: presentation)
        let unassigned = try XCTUnwrap(groups.first { $0.kind == .unassigned })
        let visibleContainer = try XCTUnwrap(unassigned.containers.first)
        XCTAssertEqual(groups.flatMap(\.containers).count, 1)
        XCTAssertNotNil(visibleContainer.ownershipError)
        XCTAssertNil(visibleContainer.resourceIdentity)
    }

    func testWholeRepositoryControlRequiresServerAndSidecarDockerCoverageFromOneSource() throws {
        let project = try repositoryPath(named: "split-control")
        let server = try server(
            origin: account,
            id: "account-web",
            name: "web",
            project: project,
            port: 3000,
            status: "stopped"
        )
        var container = try dockerContainer(
            origin: chatGPT,
            id: "sidecar-worker-id",
            name: "split-control-worker",
            project: project,
            cpu: 0,
            memory: 100,
            sampledAt: 1
        )
        container.metadataSource = "coordinator_sidecar"
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [server],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "split-control",
                    serverIDs: ["account-web"]
                )
            ),
            source(
                origin: chatGPT,
                containers: [container],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(project)",
                    project: project,
                    name: "split-control",
                    containerNames: ["split-control-worker"]
                )
            ),
        ])

        let repository = try XCTUnwrap(catalog.repositories.first)
        XCTAssertEqual(repository.servers.first?.controlCandidates, [account])
        XCTAssertEqual(repository.docker.first?.controlCandidates, [chatGPT])
        XCTAssertNil(repository.controlOrigin)
        XCTAssertTrue(repository.projectActionsBlocked)
    }

    func testSameActivePhysicalServerClaimedByTwoRepositoriesBlocksBothProjects() throws {
        let leftProject = try repositoryPath(named: "server-left")
        let rightProject = try repositoryPath(named: "server-right")
        let left = try server(
            origin: account,
            id: "left-web",
            name: "web",
            project: leftProject,
            port: 3300,
            status: "running",
            pid: 991,
            processCPU: 17,
            processMemory: 1_700,
            sampledAt: "2026-07-13T10:00:00Z"
        )
        let right = try server(
            origin: chatGPT,
            id: "right-web",
            name: "web",
            project: rightProject,
            port: 3300,
            status: "running",
            pid: 991,
            processCPU: 18,
            processMemory: 1_800,
            sampledAt: "2026-07-13T10:00:01Z"
        )
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [left],
                usage: usage(
                    origin: account,
                    key: "path:\(leftProject)",
                    project: leftProject,
                    name: "server-left",
                    serverIDs: ["left-web"]
                )
            ),
            source(
                origin: chatGPT,
                servers: [right],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(rightProject)",
                    project: rightProject,
                    name: "server-right",
                    serverIDs: ["right-web"]
                )
            ),
        ])

        XCTAssertEqual(catalog.repositories.count, 2)
        for repository in catalog.repositories {
            XCTAssertEqual(repository.serverMembershipConflicts.count, 1)
            XCTAssertTrue(repository.projectActionsBlocked)
            XCTAssertNil(repository.controlOrigin)
            XCTAssertTrue(repository.servers.isEmpty)
            XCTAssertEqual(repository.usage.serverCount, 0)
            XCTAssertEqual(repository.usage.processCount, 0)
            XCTAssertEqual(repository.usage.cpuPercent, 0)
            XCTAssertEqual(repository.usage.memoryBytes, 0)
        }
        XCTAssertEqual(catalog.unassigned.servers.count, 2, "raw provenance for both observations must remain available")
        let groups = makeProjectGroups(from: catalog, inventory: .empty)
        let unassigned = try XCTUnwrap(groups.first { !$0.isRepository })
        XCTAssertEqual(unassigned.servers.count, 1, "one physical conflict must render as one unassigned resource")
        XCTAssertNotNil(unassigned.servers.first?.ownershipError)
        XCTAssertEqual(repositoryCatalogConflictHealthSignals(catalog).count, 1)
    }

    @MainActor
    func testDockerMembershipConflictBlocksBothOtherwiseControlledProjectActionsAndHealthIsNotNominal() throws {
        let containerID = "project-action-conflict-id"
        let leftProject = try repositoryPath(named: "action-left")
        let rightProject = try repositoryPath(named: "action-right")
        let leftServer = try server(origin: account, id: "left-web", name: "web", project: leftProject, port: 3400, status: "stopped")
        let rightServer = try server(origin: chatGPT, id: "right-web", name: "web", project: rightProject, port: 3500, status: "stopped")
        var leftContainer = try dockerContainer(origin: account, id: containerID, name: "shared-action-worker", project: leftProject, cpu: 0, memory: 100, sampledAt: 1)
        var rightContainer = try dockerContainer(origin: chatGPT, id: containerID, name: "shared-action-worker", project: rightProject, cpu: 0, memory: 100, sampledAt: 2)
        leftContainer.metadataSource = "coordinator_sidecar"
        rightContainer.metadataSource = "coordinator_sidecar"
        let sources = [
            source(
                origin: account,
                servers: [leftServer],
                containers: [leftContainer],
                usage: usage(
                    origin: account,
                    key: "path:\(leftProject)",
                    project: leftProject,
                    name: "action-left",
                    serverIDs: ["left-web"],
                    containerNames: ["shared-action-worker"]
                )
            ),
            source(
                origin: chatGPT,
                servers: [rightServer],
                containers: [rightContainer],
                usage: usage(
                    origin: chatGPT,
                    key: "path:\(rightProject)",
                    project: rightProject,
                    name: "action-right",
                    serverIDs: ["right-web"],
                    containerNames: ["shared-action-worker"]
                )
            ),
        ]
        let catalog = RepositoryCatalog.build(from: sources)
        var presentation = sources[0].inventory
        presentation.servers = sources.flatMap { $0.inventory.servers }
        presentation.docker.containers = [leftContainer]
        presentation.projectUsage = sources.flatMap { $0.inventory.projectUsage }
        let groups = makeProjectGroups(from: catalog, inventory: presentation).filter(\.isRepository)
        let store = OpsStore(clock: RepositoryCatalogClock())
        store.sourceStates = [
            CoordinatorSourceState(origin: account, phase: .loaded, checkedAt: Date(), resourceCount: 1),
            CoordinatorSourceState(origin: chatGPT, phase: .loaded, checkedAt: Date(), resourceCount: 1),
        ]
        store.capabilityStates = [account, chatGPT].flatMap { origin in
            CoordinatorCapability.allCases.map {
                CoordinatorCapabilityState(origin: origin, capability: $0, phase: .available, checkedAt: Date())
            }
        }

        XCTAssertEqual(groups.count, 2)
        for group in groups {
            XCTAssertEqual(group.dockerMembershipConflicts.count, 1)
            XCTAssertFalse(store.projectMutationAvailability(kind: .projectStart, group: group).isAllowed)
        }
        let signals = repositoryCatalogConflictHealthSignals(catalog)
        XCTAssertEqual(signals.count, 1)
        let health = HealthSummary.reduce(
            sources: store.sourceStates,
            resourceSignals: signals,
            actions: [],
            now: Date()
        )
        XCTAssertEqual(health.level, .unhealthy)
        XCTAssertEqual(health.unhealthyResourceCount, 1)
    }

    func testUsageOnlyNameEvidenceStillProducesOneUnassignedPresentation() {
        let evidence = usage(
            origin: account,
            key: "name:temporarily-unobservable",
            project: nil,
            name: "temporarily-unobservable",
            containerNames: ["temporarily-unobservable"]
        )
        let source = source(origin: account, usage: evidence)
        let catalog = RepositoryCatalog.build(from: [source])
        let groups = makeProjectGroups(from: catalog, inventory: source.inventory)

        XCTAssertTrue(catalog.repositories.isEmpty)
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups.first?.kind, .unassigned)
        XCTAssertEqual(groups.first?.unassignedEvidenceCount, 1)
        XCTAssertTrue(groups.first?.containers.isEmpty == true)
    }

    func testHealthyCatalogProducesNoConflictHealthSignals() throws {
        let project = try repositoryPath(named: "healthy")
        let healthy = try server(origin: account, id: "healthy-web", name: "web", project: project, port: 3600, status: "stopped")
        let catalog = RepositoryCatalog.build(from: [
            source(
                origin: account,
                servers: [healthy],
                usage: usage(
                    origin: account,
                    key: "path:\(project)",
                    project: project,
                    name: "healthy",
                    serverIDs: ["healthy-web"]
                )
            )
        ])
        XCTAssertTrue(repositoryCatalogConflictHealthSignals(catalog).isEmpty)
    }

    private func source(
        origin: CoordinatorOrigin,
        servers: [ManagedServer] = [],
        containers: [DockerContainer] = [],
        usage: ProjectUsage? = nil
    ) -> RepositoryInventorySource {
        var inventory = Inventory(
            coordinatorHome: origin.home,
            statePath: "\(origin.home)/state.json",
            project: nil,
            urls: [],
            servers: servers,
            leases: [],
            recentEvents: [],
            docker: DockerSummary(available: true, error: nil, statsError: nil, containers: containers, postgres: []),
            postgres: [],
            backups: [],
            projectUsage: usage.map { [$0] } ?? []
        )
        inventory.origin = origin
        return RepositoryInventorySource(origin: origin, inventory: inventory)
    }

    private func repositoryPath(named name: String) throws -> String {
        let fixtureRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("repository-catalog-fixture-\(UUID().uuidString)", isDirectory: true)
        let repository = fixtureRoot.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(
            at: repository.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        repositoryFixtureRoots.append(fixtureRoot)
        return repository.path
    }

    private func catalogInventory(
        origin: CoordinatorOrigin,
        containers: [DockerContainer],
        databases: [DockerContainer],
        usage: ProjectUsage
    ) -> Inventory {
        var inventory = Inventory(
            coordinatorHome: origin.home,
            statePath: "\(origin.home)/state.json",
            project: nil,
            urls: [],
            servers: [],
            leases: [],
            recentEvents: [],
            docker: DockerSummary(available: true, error: nil, statsError: nil, containers: containers, postgres: databases),
            postgres: databases,
            backups: [],
            projectUsage: [usage]
        )
        inventory.origin = origin
        return inventory
    }

    private func usage(
        origin: CoordinatorOrigin,
        key: String,
        project: String?,
        name: String,
        serverIDs: [String] = [],
        containerNames: [String] = [],
        cpu: Double = 0,
        memory: Double = 0
    ) -> ProjectUsage {
        var row = ProjectUsage(
            usageKey: key,
            project: project,
            projectKey: project.map { URL(fileURLWithPath: $0).lastPathComponent.lowercased() } ?? name,
            name: name,
            serverIDs: serverIDs,
            containerNames: containerNames,
            serverCount: serverIDs.count,
            containerCount: containerNames.count,
            processCount: 0,
            cpuPercent: cpu,
            memoryBytes: memory,
            processCPUPercent: cpu,
            processMemoryBytes: memory,
            dockerCPUPercent: 0,
            dockerMemoryBytes: 0,
            processes: [],
            hotProcesses: []
        )
        row.origin = origin
        return row
    }

    private func server(
        origin: CoordinatorOrigin,
        id: String,
        name: String,
        project: String,
        port: Int,
        status: String,
        pid: Int? = nil,
        processCPU: Double? = nil,
        processMemory: Double? = nil,
        sampledAt: String? = nil
    ) throws -> ManagedServer {
        var object: [String: Any] = [
            "id": id,
            "name": name,
            "project": project,
            "port": port,
            "host": "127.0.0.1",
            "status": status,
            "health": [
                "ok": status == "running",
                "pid_alive": status == "running",
            ],
            "updated_at": "2026-07-13T10:00:00Z",
        ]
        if let pid { object["pid"] = pid }
        if let processCPU, let processMemory, let pid {
            object["process_usage"] = [
                "pid": pid,
                "process_count": 1,
                "cpu_percent": processCPU,
                "rss_bytes": processMemory,
                "sampled_at": sampledAt ?? "2026-07-13T10:00:00Z",
            ]
        }
        let data = try JSONSerialization.data(withJSONObject: object)
        var value = try JSONDecoder().decode(ManagedServer.self, from: data)
        value.origin = origin
        value.coordinatorID = id
        return value
    }

    private func dockerContainer(
        origin: CoordinatorOrigin,
        id: String,
        name: String,
        project: String?,
        cpu: Double,
        memory: Double,
        sampledAt: Double
    ) throws -> DockerContainer {
        var object: [String: Any] = [
            "id": id,
            "name": name,
            "image": name.contains("postgres") ? "postgres:17" : "node:22",
            "status": "Up 31 hours",
            "metadata_source": project == nil ? "none" : "docker_labels",
            "stats": [
                "container_id": id,
                "timestamp_ts": sampledAt,
                "live": true,
                "cpu_percent": cpu,
                "memory_usage_bytes": memory,
            ],
        ]
        if let project { object["project"] = project }
        let data = try JSONSerialization.data(withJSONObject: object)
        var value = try JSONDecoder().decode(DockerContainer.self, from: data)
        value.origin = origin
        return value
    }
}

private struct RepositoryCatalogClock: Clock {
    func now() -> Date { Date(timeIntervalSince1970: 1_768_219_200) }
}
