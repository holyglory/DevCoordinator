import AppKit
import CryptoKit
import Darwin
import Foundation
import OSLog
import SwiftUI

private let inventoryLogger = Logger(
    subsystem: "local.holyskills.codex-ops-console",
    category: "Inventory"
)

private let boardInventoryArguments = [
    "inventory",
    "--compact-json",
    "--stats-history-limit", "30",
]

private enum OriginInventoryExecutionResult: Sendable {
    case success(NormalizedBoardProjection)
    case failure(String)
}

private enum OriginInventoryFailureStage: String, Sendable {
    case processLaunch = "process-launch"
    case outputLimit = "output-limit"
    case timeout
    case cancelled
    case nonzeroExit = "nonzero-exit"
    case jsonDecode = "json-decode"
    case graphProjection = "graph-projection"
}

private struct OriginInventoryLoadOutcome: Sendable {
    let index: Int
    let origin: CoordinatorOrigin
    let result: OriginInventoryExecutionResult
    let observationFailure: String?
    let failureStage: OriginInventoryFailureStage?
    let failureExitStatus: Int32?
}

private func validateInventoryExecution(_ execution: CommandExecution) throws -> CommandExecution {
    if execution.outputTruncated {
        throw RuntimeError(
            "Coordinator inventory exceeded the app's \(CommandRequest.inventoryMaxOutputBytes / 1_048_576) MiB output limit"
        )
    }
    if execution.timedOut {
        throw RuntimeError("Coordinator inventory timed out")
    }
    if execution.cancelled {
        throw RuntimeError("Coordinator inventory was cancelled")
    }
    guard execution.exitStatus == 0 else {
        throw RuntimeError(execution.stderr.isEmpty ? execution.stdout : execution.stderr)
    }
    return execution
}

private func validateObservationExecution(_ execution: CommandExecution) throws {
    if execution.outputTruncated {
        throw RuntimeError("Coordinator observation output exceeded its safety limit")
    }
    if execution.timedOut {
        throw RuntimeError("Coordinator observation timed out")
    }
    if execution.cancelled {
        throw RuntimeError("Coordinator observation was cancelled")
    }
    guard execution.exitStatus == 0 else {
        throw RuntimeError(execution.stderr.isEmpty ? execution.stdout : execution.stderr)
    }
}

private func decodingFailureDiagnostic(_ error: Error) -> String {
    func path(_ context: DecodingError.Context, terminal: CodingKey? = nil) -> String {
        let components = context.codingPath.map(\.stringValue) + [terminal?.stringValue].compactMap { $0 }
        return components.isEmpty ? "root" : components.joined(separator: ".")
    }
    switch error {
    case DecodingError.keyNotFound(let key, let context):
        return "key-not-found:\(path(context, terminal: key))"
    case DecodingError.typeMismatch(_, let context):
        return "type-mismatch:\(path(context))"
    case DecodingError.valueNotFound(_, let context):
        return "value-not-found:\(path(context))"
    case DecodingError.dataCorrupted(let context):
        return "data-corrupted:\(path(context))"
    default:
        return "decoder-error"
    }
}

private func loadOriginInventory(
    index: Int,
    origin: CoordinatorOrigin,
    arguments: [String],
    observationMaxAgeSeconds: Double?,
    coordinatorService: any CoordinatorServing
) async -> OriginInventoryLoadOutcome {
    var observationFailure: String?
    if let observationMaxAgeSeconds {
        do {
            if let observation = try await coordinatorService.observe(
                origin: origin,
                maxAgeSeconds: observationMaxAgeSeconds
            ) {
                try validateObservationExecution(observation)
            }
        } catch {
            observationFailure = error.localizedDescription
        }
    }
    let initial: CommandExecution
    do {
        initial = try await coordinatorService.execute(origin: origin, arguments: arguments)
    } catch {
        return OriginInventoryLoadOutcome(
            index: index,
            origin: origin,
            result: .failure(error.localizedDescription),
            observationFailure: observationFailure,
            failureStage: .processLaunch,
            failureExitStatus: nil
        )
    }
    do {
        _ = try validateInventoryExecution(initial)
    } catch {
        let stage: OriginInventoryFailureStage = initial.outputTruncated ? .outputLimit
            : (initial.timedOut ? .timeout
                : (initial.cancelled ? .cancelled : .nonzeroExit))
        return OriginInventoryLoadOutcome(
            index: index,
            origin: origin,
            result: .failure(error.localizedDescription),
            observationFailure: observationFailure,
            failureStage: stage,
            failureExitStatus: initial.exitStatus
        )
    }
    let graph: NormalizedInventoryGraph
    do {
        graph = try JSONDecoder().decode(
            NormalizedInventoryGraph.self,
            from: Data(initial.stdout.utf8)
        )
    } catch {
        inventoryLogger.error(
            "Inventory JSON decode failed pid=\(Int(Darwin.getpid()), privacy: .public) reason=\(decodingFailureDiagnostic(error), privacy: .public)"
        )
        return OriginInventoryLoadOutcome(
            index: index,
            origin: origin,
            result: .failure(error.localizedDescription),
            observationFailure: observationFailure,
            failureStage: .jsonDecode,
            failureExitStatus: initial.exitStatus
        )
    }
    do {
        let decoded = try graph.boardProjection(origin: origin)
        return OriginInventoryLoadOutcome(
            index: index,
            origin: origin,
            result: .success(decoded),
            observationFailure: observationFailure,
            failureStage: nil,
            failureExitStatus: initial.exitStatus
        )
    } catch {
        return OriginInventoryLoadOutcome(
            index: index,
            origin: origin,
            result: .failure(error.localizedDescription),
            observationFailure: observationFailure,
            failureStage: .graphProjection,
            failureExitStatus: initial.exitStatus
        )
    }
}

enum RefreshSurface: Hashable {
    case window
    case popover
}

/// A logical server row whose identity is independent of the coordinator
/// observation currently chosen for display and control.
struct PresentedServerRow: Identifiable, Equatable {
    let id: String
    let server: ManagedServer
}

@MainActor
final class OpsStore: ObservableObject {
    static let bulkStopMaximumItems = 50
    @Published var inventory: Inventory = .empty {
        didSet {
            guard oldValue != inventory else { return }
            let catalog = stagedRepositoryCatalog ?? RepositoryCatalog.build(from: inventory)
            stagedRepositoryCatalog = nil
            publishRepositoryPresentation(catalog: catalog, inventory: inventory)
        }
    }
    @Published private(set) var repositoryCatalog: RepositoryCatalog = .empty
    @Published private(set) var projectGroups: [ProjectGroup] = []
    @Published private(set) var repositoryTrees: [RepositoryTreePresentation] = []
    @Published private(set) var repositoryTreesAreAuthoritative = false
    @Published var selectedServerID: ManagedServer.ID?
    @Published var selectedDockerID: String?
    @Published var selectedDatabaseID: String?
    @Published var selectedProjectName: String?
    @Published var sidebarSelection: SidebarSelection?
    @Published var activeTab: ResourceTab = .servers
    @Published var boardWorkspace: BoardWorkspace = .resources
    @Published var selectedActionResultID: UUID?
    @Published var selectedActivityIssueID: UUID?
    @Published var searchText = ""
    @Published var filter: ServiceFilter = .all
    @Published var isLoading = false
    @Published var lastError: String?
    @Published var lastErrorDetails: String?
    @Published var lastErrorTitle: String?
    @Published var projectPath: String
    @Published var startDraft = StartServerDraft()
    @Published var showingStartSheet = false
    @Published var showingLeaseSheet = false
    @Published var showingServerLogs = false
    @Published var repositoryDecommissionPrompt: RepositoryDecommissionPrompt?
    @Published var workerRemovalPrompt: WorkerRemovalPrompt?
    @Published var resourceAttachPrompt: ResourceAttachPrompt?
    @Published var resourceRetirementPrompt: ResourceRetirementPrompt?
    @Published private(set) var retirementRecoveryContexts: [UUID: ResourceRetirementRecoveryContext] = [:]
    @Published var serverLogTitle = "Server Logs"
    @Published var serverLogText = ""
    @Published var serverLogMetadata = ""
    @Published var leaseRange = "3000-3999"
    @Published var leaseOrigin: CoordinatorOrigin?
    @Published var projectRuntimeReports: [String: ProjectRuntimeReport] = [:]
    @Published var sourceStates: [CoordinatorSourceState] = []
    @Published var capabilityStates: [CoordinatorCapabilityState] = []
    @Published var actionResults: [UUID: RetainedActionResult] = [:]
    @Published var latestLeaseResult: LeaseActionResult?
    @Published var leaseResults: [ResourceIdentity: LeaseActionResult] = [:]
    @Published var dockerLogResults: [ResourceIdentity: String] = [:]
    @Published var logEvidence: [ResourceIdentity: RetainedLogEvidence] = [:]
    @Published var bulkSelection = BulkSelection()
    @Published var latestBulkActionResult: BulkActionResult?
    @Published var pendingBulkStopPlan: BulkStopPlan?
    @Published var backupRecords: [BackupRecord] = []
    @Published private(set) var backupVerificationInProgress: Set<String> = []
    @Published var restoreEvidence: [DatabaseIdentity: DatabaseRestoreEvidence] = [:]
    @Published var coordinatorConfiguration = CoordinatorConfiguration()
    @Published var configurationWarning: String?
    @Published var inventoryIssue: OpsIssue? {
        didSet {
            guard let oldIssue = oldValue,
                  selectedActivityIssueID == oldIssue.id
            else { return }
            if let inventoryIssue {
                selectedActionResultID = nil
                selectedActivityIssueID = inventoryIssue.id
            } else if let actionIssue {
                if let actionID = actionIssue.relatedActionID,
                   visibleActivityActionResults.contains(where: { $0.id == actionID })
                {
                    selectedActionResultID = actionID
                    selectedActivityIssueID = nil
                } else {
                    selectedActionResultID = nil
                    selectedActivityIssueID = actionIssue.id
                }
            } else {
                selectedActivityIssueID = nil
                selectedActionResultID = visibleActivityActionResults.first?.id
            }
        }
    }
    @Published var actionIssue: OpsIssue?

    private let coordinatorService: any CoordinatorServing
    private let backupService: any BackupServing
    private let commandExecutor: any CommandExecuting
    private let originDiscovery: any CoordinatorOriginDiscovering
    private let usesNormalizedAccountStore: Bool
    private let configurationStore: any CoordinatorConfigurationPersisting
    private let clock: any Clock
    private var lastErrorSource: String?
    private var inventoryByOrigin: [String: Inventory] = [:]
    private var normalizedCatalogByOrigin: [String: RepositoryCatalog] = [:]
    private var normalizedRepositoryTreesByOrigin: [String: [NormalizedRepositoryTree]] = [:]
    private var originsWithAuthoritativeRepositoryTrees = Set<String>()
    private var lastInventoryAttemptAt: Date?
    private var visibleSurfaces: Set<RefreshSurface> = []
    private var autoRefreshTask: Task<Void, Never>?
    private var activeLoad: Task<Void, Never>?
    private var followUpRequested = false
    private var verifiedBackupsByKey: [String: BackupRecord] = [:]
    private var backupVerificationTasks: [String: Task<Void, Never>] = [:]
    private var stagedRepositoryCatalog: RepositoryCatalog?
    private var stagedRepositoryTrees: [NormalizedRepositoryTree]?
    private var stagedRepositoryTreesAreAuthoritative = false

    init(
        coordinatorService: (any CoordinatorServing)? = nil,
        backupService: (any BackupServing)? = nil,
        commandExecutor: (any CommandExecuting)? = nil,
        // Accepted for initializer source compatibility only. Normalized v2
        // observations are authoritative; OpsStore never invokes this legacy
        // per-container dependency (the service remains tested independently).
        databaseDiscovery: (any DatabaseDiscovering)? = nil,
        originDiscovery: any CoordinatorOriginDiscovering = AccountCoordinatorOriginDiscovery(),
        configurationStore: any CoordinatorConfigurationPersisting = PrivateCoordinatorConfigurationStore(),
        clock: any Clock = SystemClock(),
        skillLocator: any SkillLocating = PortableSkillLocator()
    ) {
        let executor = commandExecutor ?? SystemCommandExecutor()
        self.commandExecutor = executor
        _ = databaseDiscovery
        self.originDiscovery = originDiscovery
        usesNormalizedAccountStore = originDiscovery is AccountCoordinatorOriginDiscovery
        self.configurationStore = configurationStore
        self.coordinatorService = coordinatorService ?? LocatedCoordinatorService(executor: executor, locator: skillLocator)
        self.backupService = backupService ?? LocatedBackupService(executor: executor, locator: skillLocator)
        self.clock = clock
        projectPath = ""
        let configurationLoad = configurationStore.load()
        coordinatorConfiguration = configurationLoad.configuration ?? CoordinatorConfiguration()
        configurationWarning = configurationLoad.warning
        if let warning = configurationLoad.warning {
            inventoryIssue = OpsIssue(
                kind: .configuration,
                title: "Coordinator configuration needs attention",
                summary: warning,
                details: warning,
                createdAt: clock.now()
            )
        }
    }

    private func publishRepositoryPresentation(catalog: RepositoryCatalog, inventory: Inventory) {
        if catalog != repositoryCatalog { repositoryCatalog = catalog }
        let groups = makeProjectGroups(from: catalog, inventory: inventory)
        if groups != projectGroups { projectGroups = groups }
        let definitions = stagedRepositoryTreesAreAuthoritative
            ? (stagedRepositoryTrees ?? [])
            : []
        if repositoryTreesAreAuthoritative != stagedRepositoryTreesAreAuthoritative {
            repositoryTreesAreAuthoritative = stagedRepositoryTreesAreAuthoritative
        }
        stagedRepositoryTrees = nil
        stagedRepositoryTreesAreAuthoritative = false
        let trees = makeRepositoryTreePresentations(groups: groups, definitions: definitions)
        if trees != repositoryTrees { repositoryTrees = trees }
    }

    private func publishInventory(
        _ decoded: Inventory,
        catalog: RepositoryCatalog,
        repositoryTreeDefinitions: [NormalizedRepositoryTree]?
    ) {
        stagedRepositoryTrees = repositoryTreeDefinitions
        stagedRepositoryTreesAreAuthoritative = repositoryTreeDefinitions != nil
        let needsInventoryPublication = decoded != inventory
            || !inventoryUsesCurrentSourcePresentation(inventory)
        if needsInventoryPublication {
            stagedRepositoryCatalog = catalog
            inventory = decoded
        } else {
            publishRepositoryPresentation(catalog: catalog, inventory: decoded)
        }
    }

    var selectedServer: ManagedServer? {
        guard let selectedServerID else { return nil }
        return presentedServerRows.first { $0.id == selectedServerID }?.server
            ?? inventory.servers.first { serverSelectionID(for: $0) == selectedServerID }
    }

    var selectedDocker: DockerContainer? {
        guard let selectedDockerID else { return nil }
        return inventory.docker.containers.first { $0.containerSelectionID == selectedDockerID }
    }

    var selectedDatabase: DockerContainer? {
        guard let selectedDatabaseID else { return nil }
        return inventory.postgres.first { $0.databaseSelectionID == selectedDatabaseID }
    }

    var unassignedProjectGroup: ProjectGroup? {
        // Association failures are diagnostics, never a synthetic repository.
        // Missing producer-owned hierarchy renders an incompatible state.
        nil
    }

    var repositoryTreeContractUnavailable: Bool {
        !repositoryTreesAreAuthoritative && sourceStates.contains {
            $0.phase == .loaded || $0.phase == .stale
        }
    }

    var authoritativeAssociationMutationsBlocked: Bool {
        authoritativeAssociationProblemCount > 0
    }

    private var authoritativeAssociationProblemCount: Int {
        guard repositoryTreesAreAuthoritative else { return 0 }
        var identities = Set<String>()
        for server in inventory.servers
            where server.attribution != nil || server.associationError != nil {
            identities.insert("server|\(server.coordinatorID ?? server.id)")
        }
        for container in inventory.docker.containers
            where container.attribution != nil || container.associationError != nil {
            identities.insert("container|\(container.attribution?.hostResourceID ?? container.id ?? container.stableID)")
        }
        return identities.count
    }

    private var authoritativeAssociationBlockMessage: String? {
        let count = authoritativeAssociationProblemCount
        guard count > 0 else { return nil }
        return "The coordinator reports \(count) resource\(count == 1 ? "" : "s") without safe lifecycle association. Review the exact reason and next step in the attention banner or affected resource, resolve it with the Coordinator skill, then refresh."
    }

    private func isOrdinaryRuntimeMutation(_ kind: ActionKind) -> Bool {
        switch kind {
        case .startServer, .stopServer, .restartServer,
             .startWorker, .stopWorker, .restartWorker, .setWorkerKeepAlive,
             .startDocker, .stopDocker, .restartDocker,
             .leasePort, .releasePort,
             .projectStart, .projectStop, .projectRestart,
             .backupDatabase, .verifyBackup, .restoreDatabase:
            return true
        case .refreshInventory, .serverLogs, .dockerLogs, .projectStatus,
             .repositoryDecommissionPlan, .repositoryDecommission,
             .workerRemovalPlan, .workerRemovalApply,
             .attachResource, .retireStandaloneResource:
            // Read-only inspection and the exact corrective association/removal
            // journeys remain available; unrelated runtime mutation does not.
            return false
        }
    }

    func repositoryBreadcrumb(for server: ManagedServer) -> String {
        let nativeID = server.coordinatorID ?? server.id
        for tree in repositoryTrees {
            if let scope = tree.scopes.first(where: { scope in
                scope.definition.serverIDs.contains(nativeID)
            }) {
                return scope.breadcrumb(rootName: tree.root.displayName)
            }
        }
        return projectDisplayLabel(server.project)
    }

    func repositoryBreadcrumb(for container: DockerContainer) -> String {
        let selectionID = container.database == nil
            ? container.containerSelectionID
            : container.databaseSelectionID
        for tree in repositoryTrees {
            if let scope = tree.scopes.first(where: { scope in
                if container.database == nil {
                    return scope.group.containers.contains {
                        $0.containerSelectionID == selectionID
                    }
                }
                return scope.group.databases.contains {
                    $0.databaseSelectionID == selectionID
                }
            }) {
                return scope.breadcrumb(rootName: tree.root.displayName)
            }
        }
        return projectLabel(for: container, in: projectGroups)
    }

    var filteredServerRows: [PresentedServerRow] {
        presentedServerRows.filter { row in
            let server = row.server
            let status = (server.status ?? "").lowercased()
            let matchesFilter: Bool
            switch filter {
            case .all:
                matchesFilter = true
            case .running:
                matchesFilter = status == "running"
            case .unhealthy:
                matchesFilter = serverRequiresAttention(server) && hasLoadedEvidence(
                    primary: server.origin,
                    observations: server.observationOrigins
                )
            case .stopped:
                matchesFilter = status == "stopped"
            }

            guard matchesFilter else { return false }
            let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !query.isEmpty else { return true }
            return [server.name, server.project, server.url, server.agent, server.logPath]
                .compactMap { $0?.lowercased() }
                .contains { $0.contains(query) }
        }
    }

    var filteredServers: [ManagedServer] {
        filteredServerRows.map(\.server)
    }

    /// Repository-catalog representatives are the user-facing server rows.
    /// Raw source records remain in `inventory.servers` for provenance and
    /// exact action reconciliation, but repeated observations of one logical
    /// service must not inflate the Board.
    private var presentedServerRows: [PresentedServerRow] {
        var seen = Set<String>()
        return projectGroups.flatMap { group in
            group.servers.compactMap { server in
                let id = serverSelectionID(for: server, in: group)
                guard seen.insert(id).inserted else { return nil }
                return PresentedServerRow(id: id, server: server)
            }
        }
    }

    private var presentedServers: [ManagedServer] {
        presentedServerRows.map(\.server)
    }

    /// Match the repository catalog's logical service identity for every
    /// visible repository row. Unassigned evidence deliberately remains bound
    /// to its exact source-qualified observation.
    func serverSelectionID(for server: ManagedServer) -> String {
        if let presented = presentedServerRows.first(where: { $0.server.id == server.id }) {
            return presented.id
        }
        if let repository = [server.project, server.cwd]
            .compactMap({ RepositoryIdentity(projectPath: $0) })
            .first
        {
            return RepositoryLogicalServerIdentity(
                repository: repository,
                serviceName: server.name
            ).id
        }
        return "server-observation:\(server.id)"
    }

    private func serverSelectionID(for server: ManagedServer, in group: ProjectGroup) -> String {
        if group.isRepository,
           let repository = RepositoryIdentity(projectPath: group.projectPath)
        {
            return RepositoryLogicalServerIdentity(
                repository: repository,
                serviceName: server.name
            ).id
        }
        return "server-observation:\(server.id)"
    }

    var visibleDockerContainers: [DockerContainer] {
        filterDocker(inventory.docker.containers)
    }

    var visiblePostgres: [DockerContainer] {
        filterDocker(inventory.postgres)
    }

    var connected: Bool {
        sourceStates.contains { $0.phase == .loaded }
    }

    /// A Docker-specific warning is evidence-backed only when its coordinator
    /// source loaded successfully. A transport/source failure makes Docker
    /// unknown, not unavailable.
    var explicitlyUnavailableDockerCapabilities: [CoordinatorCapabilityState] {
        let loadedOriginIDs = Set(sourceStates.filter { $0.phase == .loaded }.map { $0.origin.id })
        return capabilityStates.filter {
            $0.capability == .docker
                && $0.phase == .unavailable
                && loadedOriginIDs.contains($0.origin.id)
        }
    }

    /// Resource attention is recomputed only from currently loaded source
    /// evidence. Retained stale inventory remains visible, but it cannot make
    /// a new assertion that a resource presently requires intervention.
    var resourceAttentionItems: [ResourceAttentionItem] {
        var items: [ResourceAttentionItem] = []

        // Producer-reported unassigned resources remain visible as actionable
        // diagnostics, never as a synthetic project beside the exact tree.
        // Each item supplies a concrete explanation, next step, and review
        // route rather than collapsing the entire inventory into an
        // unavailable state.
        if repositoryTreesAreAuthoritative {
            for observation in repositoryCatalog.unassigned.servers {
                let server = observation.server
                guard let attribution = server.attribution,
                      !attribution.lifecycleViolation,
                      hasLoadedEvidence(primary: server.origin, observations: server.observationOrigins)
                else { continue }
                let selectionID = serverSelectionID(for: server)
                items.append(
                    ResourceAttentionItem(
                        id: "unassigned:server:\(selectionID)",
                        kind: .server,
                        title: "\(server.name) is not assigned to a repository",
                        reason: attribution.explanation,
                        recommendedNextStep: attribution.recommendedNextStep
                            ?? "Rerun Coordinator installation for the root repository, or attach or retire this exact server.",
                        reviewTarget: AttentionReviewTarget(kind: .server, selectionID: selectionID)
                    )
                )
            }
            for resource in repositoryCatalog.unassigned.docker {
                let container = resource.representative
                guard let attribution = container.attribution,
                      !attribution.lifecycleViolation,
                      hasLoadedEvidence(primary: container.origin, observations: container.observationOrigins)
                else { continue }
                let selectionID = container.containerSelectionID
                items.append(
                    ResourceAttentionItem(
                        id: "unassigned:docker:\(selectionID)",
                        kind: .docker,
                        title: "\(container.name ?? "Docker container") is not assigned to a repository",
                        reason: attribution.explanation,
                        recommendedNextStep: attribution.recommendedNextStep
                            ?? "Rerun Coordinator installation for the root repository, or attach or retire this exact container.",
                        reviewTarget: AttentionReviewTarget(kind: .docker, selectionID: selectionID)
                    )
                )
            }
        }

        // A completed removal is normally absent from the active projection.
        // If a later host observation proves one of its exact resources is
        // running, that is a critical lifecycle invariant violation—not a new
        // project and not an ordinary unassigned-resource suggestion.
        for row in presentedServerRows {
            let server = row.server
            guard let attribution = server.attribution,
                  attribution.lifecycleViolation,
                  hasLoadedEvidence(primary: server.origin, observations: server.observationOrigins)
            else { continue }
            items.append(
                ResourceAttentionItem(
                    id: "start-fence-violation:server:\(row.id)",
                    kind: .server,
                    title: "\(server.name) is running after removal",
                    reason: attribution.explanation,
                    recommendedNextStep: attribution.recommendedNextStep
                        ?? "Stop this exact server and resume its retained removal operation with the Coordinator skill.",
                    reviewTarget: AttentionReviewTarget(kind: .server, selectionID: row.id)
                )
            )
        }

        var seenFenceViolationContainers = Set<String>()
        for container in inventory.docker.containers {
            let selectionID = container.containerSelectionID
            guard let attribution = container.attribution,
                  attribution.lifecycleViolation,
                  seenFenceViolationContainers.insert(selectionID).inserted,
                  hasLoadedEvidence(primary: container.origin, observations: container.observationOrigins)
            else { continue }
            items.append(
                ResourceAttentionItem(
                    id: "start-fence-violation:docker:\(selectionID)",
                    kind: .docker,
                    title: "\(container.name ?? "Docker container") is running after removal",
                    reason: attribution.explanation,
                    recommendedNextStep: attribution.recommendedNextStep
                        ?? "Stop this exact container and resume its retained removal operation with the Coordinator skill.",
                    reviewTarget: AttentionReviewTarget(kind: .docker, selectionID: selectionID)
                )
            )
        }

        for row in presentedServerRows {
            let server = row.server
            guard server.resourceIdentity != nil,
                  server.attribution?.lifecycleViolation != true,
                  serverRequiresAttention(server),
                  hasLoadedEvidence(primary: server.origin, observations: server.observationOrigins)
            else { continue }
            let status = (server.status ?? "unknown")
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            let isExplicitFailure = ["unhealthy", "degraded", "orphaned"].contains(status)
            let title = isExplicitFailure
                ? "\(server.name) is \(status)"
                : "\(server.name) health check failed"
            let reason: String
            if isExplicitFailure {
                let stoppedReason = server.stoppedReason?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                reason = stoppedReason.isEmpty
                    ? "The coordinator reports the server state as \(status)."
                    : stoppedReason
            } else {
                reason = "The server is running, but its current health check reports failure."
            }
            items.append(
                ResourceAttentionItem(
                    id: "server-health:\(row.id)",
                    kind: .server,
                    title: title,
                    reason: reason,
                    recommendedNextStep: "Review the server logs and diagnostics, then restart it only if the failure persists.",
                    reviewTarget: AttentionReviewTarget(kind: .server, selectionID: row.id)
                )
            )
        }

        var seenDocker = Set<String>()
        for container in inventory.docker.containers {
            let selectionID = container.containerSelectionID
            guard seenDocker.insert(selectionID).inserted,
                  container.resourceIdentity != nil,
                  container.attribution?.lifecycleViolation != true,
                  dockerRequiresAttention(container),
                  hasLoadedEvidence(primary: container.origin, observations: container.observationOrigins)
            else { continue }
            let status = (container.status ?? "unknown").trimmingCharacters(in: .whitespacesAndNewlines)
            let name = container.name ?? "Docker container"
            items.append(
                ResourceAttentionItem(
                    id: "docker-health:\(selectionID)",
                    kind: .docker,
                    title: "\(name) needs attention",
                    reason: "Docker reports \(status).",
                    recommendedNextStep: "Review the container diagnostics and logs before restarting it.",
                    reviewTarget: AttentionReviewTarget(kind: .docker, selectionID: selectionID)
                )
            )
        }

        var seenConflicts = Set<String>()
        for repository in repositoryCatalog.repositories {
            let projectGroupID = repository.identity.repoID.map { "repo:\($0)" }
                ?? "path:\(repository.identity.canonicalRoot)"
            let projectTarget = AttentionReviewTarget(kind: .project, selectionID: projectGroupID)
            for conflict in repository.serverConflicts
                where seenConflicts.insert("server-endpoint:\(conflict.id)").inserted
                    && hasFullyLoadedEvidence(origins: conflict.activeSourceIdentities.map { $0.origin })
            {
                items.append(
                    ResourceAttentionItem(
                        id: "project-conflict:server-endpoint:\(conflict.id)",
                        kind: .projectConflict,
                        title: "\(repository.displayName) has conflicting active servers",
                        reason: conflict.message,
                        recommendedNextStep: "Review project diagnostics and resolve the competing server records before running project actions.",
                        reviewTarget: projectTarget
                    )
                )
            }
            for conflict in repository.serverAssociationConflicts
                where seenConflicts.insert("server-association:\(conflict.id)").inserted
                    && hasFullyLoadedEvidence(origins: conflict.activeSourceIdentities.map { $0.origin })
            {
                let conflictedIdentities = Set(conflict.activeSourceIdentities.map(\.rawValue))
                let row = presentedServerRows.first { candidate in
                    conflictedIdentities.contains(candidate.server.id)
                        || !Set(candidate.server.observationOrigins.map(\.id)).isDisjoint(
                            with: Set(conflict.activeSourceIdentities.map { $0.origin.id })
                        ) && candidate.server.associationError == conflict.message
                }
                guard let row else { continue }
                let target = AttentionReviewTarget(kind: .server, selectionID: row.id)
                let repositories = conflict.repositories.map(\.displayName).joined(separator: ", ")
                let resourceName = row.server.name
                items.append(
                    ResourceAttentionItem(
                        id: "project-conflict:server-association:\(conflict.id)",
                        kind: .projectConflict,
                        title: "\(resourceName) has conflicting project association",
                        reason: "\(conflict.message) Candidate repositories: \(repositories).",
                        recommendedNextStep: "Review the server diagnostics and correct its repository attribution before acting.",
                        reviewTarget: target
                    )
                )
            }
            for conflict in repository.dockerAssociationConflicts
                where seenConflicts.insert("docker-association:\(conflict.id)").inserted
                    && hasFullyLoadedEvidence(origins: conflict.sourceIdentities.map { $0.origin })
            {
                guard let physical = repositoryCatalog.unassigned.docker.first(where: {
                    $0.identity == conflict.resource
                }) else { continue }
                let selectionID = physical.representative.containerSelectionID
                let resourceName = physical.representative.name ?? "Docker container"
                let repositories = conflict.repositories.map(\.displayName).joined(separator: ", ")
                items.append(
                    ResourceAttentionItem(
                        id: "project-conflict:docker-association:\(conflict.id)",
                        kind: .projectConflict,
                        title: "\(resourceName) has conflicting project association",
                        reason: "\(conflict.message) Candidate repositories: \(repositories).",
                        recommendedNextStep: "Review the container diagnostics and correct its repository attribution before acting.",
                        reviewTarget: AttentionReviewTarget(kind: .docker, selectionID: selectionID)
                    )
                )
            }
        }

        return items.sorted {
            if $0.kind != $1.kind { return $0.kind.rawValue < $1.kind.rawValue }
            return $0.id < $1.id
        }
    }

    var healthSummary: HealthSummary {
        HealthSummary.reduce(
            sources: sourceStates,
            resourceSignals: resourceHealthSignals,
            actions: Array(actionResults.values),
            now: clock.now()
        )
    }

    var presentationSnapshot: OpsPresentationSnapshot {
        OpsPresentationSnapshot.reduce(
            health: healthSummary,
            sources: sourceStates,
            inventoryIssue: inventoryIssue,
            actionIssue: actionIssue,
            capabilities: capabilityStates,
            resourceAttentionItems: resourceAttentionItems
        )
    }

    var refreshIntervalSeconds: Double? {
        coordinatorConfiguration.refreshPolicy.mode == .interval
            ? coordinatorConfiguration.refreshPolicy.intervalSeconds
            : nil
    }

    var usesNormalizedAccountCoordinator: Bool {
        usesNormalizedAccountStore
    }

    /// Blocking loading presentation is reserved for the first snapshot. A
    /// background refresh keeps the last proven source/resource state visible
    /// until replacement evidence arrives.
    var isInitialInventoryLoading: Bool {
        isLoading && (sourceStates.isEmpty || sourceStates.allSatisfy { $0.phase == .loading })
    }

    var scopedProjectPath: String? {
        let trimmed = projectPath.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    var actionProjectPath: String {
        scopedProjectPath ?? FileManager.default.currentDirectoryPath
    }

    var startDraftResourceIdentity: ResourceIdentity? {
        guard let origin = startDraft.origin else { return nil }
        return startDraftResourceIdentity(origin: origin)
    }

    private func startDraftResourceIdentity(origin: CoordinatorOrigin) -> ResourceIdentity? {
        let name = startDraft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return nil }
        let draftProject = startDraft.project.trimmingCharacters(in: .whitespacesAndNewlines)
        let project = draftProject.isEmpty ? actionProjectPath : draftProject
        return ResourceIdentity(origin: origin, kind: .server, nativeID: "\(project)::\(name)")
    }

    var availableActionOrigins: [CoordinatorOrigin] {
        var seen = Set<String>()
        return sourceStates
            .filter { $0.phase == .loaded }
            .map(\.origin)
            .filter { seen.insert($0.id).inserted }
            .sorted { lhs, rhs in
                if lhs.label == rhs.label { return lhs.home < rhs.home }
                return lhs.label.localizedCaseInsensitiveCompare(rhs.label) == .orderedAscending
            }
    }

    var manageableLeaseResults: [LeaseActionResult] {
        leaseResults.values
            .filter { $0.phase == .active || $0.phase == .unavailable }
            .sorted { lhs, rhs in
                let lhsExpiry = lhs.expiresAtISO.flatMap(parseISOTimestamp) ?? .distantFuture
                let rhsExpiry = rhs.expiresAtISO.flatMap(parseISOTimestamp) ?? .distantFuture
                if lhsExpiry == rhsExpiry { return lhs.identity.rawValue < rhs.identity.rawValue }
                return lhsExpiry < rhsExpiry
            }
    }

    private var agentID: String {
        NSUserName()
    }

    // MARK: - Refresh scheduling

    /// Auto-refresh honors the configured policy and runs only while a surface
    /// is visible. A hidden app spawns no coordinator commands.
    func setSurfaceVisible(_ surface: RefreshSurface, _ visible: Bool) {
        let wasVisible = !visibleSurfaces.isEmpty
        if visible {
            visibleSurfaces.insert(surface)
        } else {
            visibleSurfaces.remove(surface)
        }
        let isVisible = !visibleSurfaces.isEmpty
        guard wasVisible != isVisible else { return }
        if !isVisible {
            autoRefreshTask?.cancel()
            autoRefreshTask = nil
        } else {
            requestRefresh(force: false)
            restartAutoRefreshTask()
        }
    }

    private func restartAutoRefreshTask() {
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
        guard !visibleSurfaces.isEmpty,
              let interval = refreshIntervalSeconds,
              interval > 0
        else { return }
        autoRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(interval))
                } catch {
                    return
                }
                guard !Task.isCancelled else { return }
                // Wait for the requested load to finish before starting the
                // next idle interval. Inventory includes Docker's no-stream
                // stats sample, which can take seconds; fixed start-to-start
                // polling otherwise makes the loading UI nearly permanent and
                // continuously respawns expensive observation commands.
                await self?.loadInventory(force: false)
            }
        }
    }

    func refresh() {
        requestRefresh(force: true)
    }

    /// Coalesces concurrent refreshes into one in-flight load. A forced request
    /// arriving mid-load queues exactly one follow-up pass so callers that just
    /// mutated state still observe post-mutation inventory.
    private func requestRefresh(force: Bool) {
        if activeLoad != nil {
            if force { followUpRequested = true }
            return
        }
        activeLoad = Task { [weak self] in
            await self?.runLoadLoop(initialForce: force)
        }
    }

    private func runLoadLoop(initialForce: Bool) async {
        var force = initialForce
        repeat {
            followUpRequested = false
            await performLoadInventory(force: force)
            force = true
        } while followUpRequested
        activeLoad = nil
    }

    func loadInventory(force: Bool = false) async {
        requestRefresh(force: force)
        await activeLoad?.value
    }

    private var defaultActionOrigin: CoordinatorOrigin? {
        let loaded = availableActionOrigins
        return loaded.count == 1 ? loaded[0] : nil
    }

    private func reportMissingAssociation(_ action: String) {
        setLastError(
            title: "\(action) unavailable",
            summary: "The resource's coordinator source is unknown",
            details: "Refresh inventory before acting. The Board will not route a resource through a guessed coordinator home.",
            source: "action"
        )
    }

    private func reportAmbiguousSource(_ action: String) {
        setLastError(
            title: "\(action) requires a coordinator source",
            summary: "More than one coordinator source is active",
            details: "Select an existing source-owned resource. New resource actions cannot guess between coordinator homes.",
            source: "action"
        )
    }

    func mutationAvailability(
        kind: ActionKind,
        origin: CoordinatorOrigin,
        resource: ResourceIdentity?,
        leaseID: String? = nil,
        projectPath: String? = nil,
        projectRequiresDocker: Bool = false
    ) -> MutationAvailability {
        guard let source = sourceStates.first(where: { $0.origin.id == origin.id }) else {
            return .blocked(.unknownSource, "Coordinator source \(origin.label) is not part of the current inventory")
        }
        switch source.phase {
        case .loaded:
            break
        case .loading:
            return .blocked(.loadingSource, "Coordinator source \(origin.label) is still loading")
        case .stale:
            return .blocked(.staleSource, "Coordinator source \(origin.label) is stale; refresh it before acting")
        case .failed:
            return .blocked(.failedSource, "Coordinator source \(origin.label) is unavailable; refresh it before acting")
        }
        if isOrdinaryRuntimeMutation(kind),
           let message = authoritativeAssociationBlockMessage {
            return .blocked(.invalidResource, message)
        }
        let capability = requiredCapability(for: kind, projectRequiresDocker: projectRequiresDocker)
        if capability != .coordinator {
            guard let state = capabilityStates.first(where: {
                $0.origin.id == origin.id && $0.capability == capability
            }) else {
                return .blocked(
                    .unknownCapability,
                    "\(capability.displayName) capability status is unknown for \(origin.label); refresh inventory before acting"
                )
            }
            guard state.phase == .available else {
                let reason = state.error?.trimmingCharacters(in: .whitespacesAndNewlines)
                let suffix = reason.flatMap { $0.isEmpty ? nil : ": \($0)" } ?? ""
                return .blocked(
                    .unavailableCapability,
                    "\(capability.displayName) capability is unavailable for \(origin.label)\(suffix)"
                )
            }
        }
        let requestedConflictKeys = actionConflictKeys(
            kind: kind,
            origin: origin,
            resource: resource,
            leaseID: leaseID,
            projectPath: projectPath ?? projectPathForConflict(resource: resource)
        )
        let duplicate = actionResults.values.contains { result in
            guard result.phase == .queued || result.phase == .running else { return false }
            guard let runningOrigin = result.request.origin else { return false }
            let runningKeys = actionConflictKeys(
                kind: result.request.kind,
                origin: runningOrigin,
                resource: result.request.resource,
                leaseID: result.request.leaseID,
                projectPath: result.request.projectPath
            )
            return !requestedConflictKeys.isDisjoint(with: runningKeys)
        }
        if duplicate {
            return .blocked(.duplicateAction, "Another action is already queued or running for this target")
        }
        return .available
    }

    func projectMutationAvailability(kind: ActionKind, group: ProjectGroup) -> MutationAvailability {
        guard let projectPath = group.projectPath?.trimmingCharacters(in: .whitespacesAndNewlines),
              !projectPath.isEmpty
        else {
            return .blocked(.invalidResource, "No canonical project path is available")
        }
        guard group.isRepository else {
            return .blocked(.invalidResource, "Unassigned resources do not have a repository runtime")
        }
        guard group.serverConflicts.isEmpty else {
            return .blocked(.invalidResource, "The repository has conflicting active server observations")
        }
        guard group.serverAssociationConflicts.isEmpty else {
            return .blocked(.invalidResource, "A server resource is claimed by several repository paths")
        }
        guard group.dockerAssociationConflicts.isEmpty else {
            return .blocked(.invalidResource, "A Docker container is claimed by several repositories")
        }
        guard let origin = group.actionOrigin else {
            return .blocked(.invalidResource, "The repository does not have one proven coordinator routing identity")
        }
        let identity = ResourceIdentity(
            origin: origin,
            kind: .project,
            nativeID: group.repositoryID ?? projectPath
        )
        let knownReportRequiresDocker = projectRuntimeReports[group.id]?.requiresDockerRuntime == true
        return mutationAvailability(
            kind: kind,
            origin: origin,
            resource: identity,
            projectPath: projectPath,
            projectRequiresDocker: group.hasObservedDockerRuntime || knownReportRequiresDocker
        )
    }

    private func actionConflictKeys(
        kind: ActionKind,
        origin: CoordinatorOrigin,
        resource: ResourceIdentity?,
        leaseID: String?,
        projectPath: String?
    ) -> Set<String> {
        let source = origin.id
        var keys = Set<String>()
        if let leaseID, !leaseID.isEmpty {
            keys.insert("\(source)|lease|\(leaseID)")
        }
        if let projectPath,
           !projectPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        {
            let canonical = URL(fileURLWithPath: projectPath).standardizedFileURL.path
            keys.insert("\(source)|project|\(canonical)")
        }
        guard let resource else {
            keys.insert("\(source)|unscoped|\(kind.rawValue)")
            return keys
        }
        switch resource.kind {
        case .server:
            keys.insert("\(source)|server|\(resource.nativeID)")
        case .docker:
            keys.insert("\(source)|container|\(resource.nativeID)")
        case .database:
            let containerID = resource.nativeID.split(separator: "/", maxSplits: 1).first.map(String.init)
                ?? resource.nativeID
            keys.insert("\(source)|container|\(containerID)")
            keys.insert("\(source)|database|\(resource.nativeID)")
        case .lease:
            keys.insert("\(source)|lease|\(resource.nativeID)")
        case .project:
            keys.insert("\(source)|project|\(resource.nativeID)")
        }
        return keys
    }

    private func projectPathForConflict(resource: ResourceIdentity?) -> String? {
        guard let resource else { return nil }
        switch resource.kind {
        case .project:
            return resource.nativeID
        case .server:
            if let server = inventory.servers.first(where: { $0.resourceIdentity == resource }) {
                return server.project
            }
            if let separator = resource.nativeID.range(of: "::") {
                return String(resource.nativeID[..<separator.lowerBound])
            }
            return nil
        case .docker, .database:
            let containerID = resource.nativeID.split(separator: "/", maxSplits: 1).first.map(String.init)
                ?? resource.nativeID
            return (inventory.docker.containers + inventory.postgres).first(where: { container in
                container.origin?.id == resource.origin.id
                    && (container.id == containerID || container.name == containerID)
            })?.project
        case .lease:
            return leaseResults[resource]?.project
        }
    }

    private func requiredCapability(
        for kind: ActionKind,
        projectRequiresDocker: Bool = false
    ) -> CoordinatorCapability {
        if projectRequiresDocker,
           (kind == .projectStart || kind == .projectStop || kind == .projectRestart)
        {
            return .docker
        }
        switch kind {
        case .startDocker, .stopDocker, .restartDocker, .dockerLogs:
            return .docker
        case .backupDatabase, .verifyBackup, .restoreDatabase:
            return .database
        case .refreshInventory,
             .startServer, .stopServer, .restartServer, .serverLogs,
             .startWorker, .stopWorker, .restartWorker, .setWorkerKeepAlive,
             .workerRemovalPlan, .workerRemovalApply,
             .leasePort, .releasePort,
             .projectStatus, .projectStart, .projectStop, .projectRestart,
             .repositoryDecommissionPlan, .repositoryDecommission,
             .attachResource, .retireStandaloneResource:
            return .coordinator
        }
    }

    @discardableResult
    private func requireMutationAvailability(
        title: String,
        kind: ActionKind,
        origin: CoordinatorOrigin,
        resource: ResourceIdentity?,
        leaseID: String? = nil,
        projectPath: String? = nil
    ) -> Bool {
        let availability = mutationAvailability(
            kind: kind,
            origin: origin,
            resource: resource,
            leaseID: leaseID,
            projectPath: projectPath
        )
        guard availability.isAllowed else {
            setLastError(
                title: "\(title) unavailable",
                summary: availability.message ?? "The action is unavailable",
                details: availability.message ?? "The action is unavailable",
                source: "action"
            )
            return false
        }
        return true
    }

    private var loadedSourceIDs: Set<String> {
        Set(sourceStates.filter { $0.phase == .loaded }.map { $0.origin.id })
    }

    private func hasLoadedEvidence(
        primary: CoordinatorOrigin?,
        observations: [CoordinatorOrigin]
    ) -> Bool {
        hasLoadedEvidence(origins: [primary].compactMap { $0 } + observations)
    }

    private func hasLoadedEvidence(origins: [CoordinatorOrigin]) -> Bool {
        !Set(origins.map(\.id)).isDisjoint(with: loadedSourceIDs)
    }

    private func hasFullyLoadedEvidence(origins: [CoordinatorOrigin]) -> Bool {
        let originIDs = Set(origins.map(\.id))
        return !originIDs.isEmpty && originIDs.isSubset(of: loadedSourceIDs)
    }

    private var resourceHealthSignals: [ResourceHealthSignal] {
        resourceAttentionItems.compactMap { item in
            let observedIdentity: ResourceIdentity?
            switch item.reviewTarget.kind {
            case .server:
                observedIdentity = presentedServerRows
                    .first { $0.id == item.reviewTarget.selectionID }?
                    .server.resourceIdentity
            case .docker:
                observedIdentity = inventory.docker.containers
                    .first { $0.containerSelectionID == item.reviewTarget.selectionID }?
                    .resourceIdentity
            case .project:
                guard let group = projectGroups.first(where: { $0.id == item.reviewTarget.selectionID }),
                      let origin = group.observedOrigins.first(where: { loadedSourceIDs.contains($0.id) })
                else { return nil }
                observedIdentity = ResourceIdentity(origin: origin, kind: .project, nativeID: item.id)
            }
            let signalKind: ResourceKind = item.reviewTarget.kind == .docker ? .docker
                : (item.reviewTarget.kind == .server ? .server : .project)
            let identity = observedIdentity ?? sourceStates
                .filter { $0.phase == .loaded }
                .map(\.origin)
                .sorted { $0.id < $1.id }
                .first
                .map { ResourceIdentity(origin: $0, kind: signalKind, nativeID: item.id) }
            return identity.map { ResourceHealthSignal(identity: $0, level: .unhealthy, reason: item.reason) }
        }
    }

    @discardableResult
    func saveCoordinatorConfiguration(_ configuration: CoordinatorConfiguration) -> Bool {
        do {
            var effectiveConfiguration = configuration
            if usesNormalizedAccountStore {
                // Legacy homes are imported once by the account coordinator;
                // they are never independently polled Board sources.
                effectiveConfiguration.sources = []
            }
            let validated = try effectiveConfiguration.validated()
            try configurationStore.save(validated)
            coordinatorConfiguration = validated
            restartAutoRefreshTask()
            configurationWarning = nil
            if inventoryIssue?.kind == .configuration { inventoryIssue = nil }
            return true
        } catch {
            let message = error.localizedDescription
            configurationWarning = message
            inventoryIssue = OpsIssue(
                kind: .configuration,
                title: "Coordinator configuration could not be saved",
                summary: message,
                details: message,
                createdAt: clock.now()
            )
            setLastError(
                title: "Coordinator configuration could not be saved",
                summary: message,
                details: message,
                source: "configuration"
            )
            return false
        }
    }

    func reloadCoordinatorConfiguration() {
        let result = configurationStore.load()
        if let configuration = result.configuration {
            coordinatorConfiguration = configuration
            restartAutoRefreshTask()
        }
        configurationWarning = result.warning
        if let warning = result.warning {
            inventoryIssue = OpsIssue(
                kind: .configuration,
                title: "Coordinator configuration needs attention",
                summary: warning,
                details: warning,
                createdAt: clock.now()
            )
        } else if inventoryIssue?.kind == .configuration {
            inventoryIssue = nil
        }
    }

    private func originsForRefresh() -> [CoordinatorOrigin] {
        var byHome: [String: CoordinatorOrigin] = [:]
        for origin in originDiscovery.origins() { byHome[origin.id] = origin }
        if usesNormalizedAccountStore {
            return byHome.values.sorted { $0.id < $1.id }
        }
        for source in coordinatorConfiguration.sources {
            let origin = source.origin
            if source.enabled {
                byHome[origin.id] = origin
            } else {
                byHome.removeValue(forKey: origin.id)
            }
        }
        return byHome.values.sorted { $0.id < $1.id }
    }

    private func performLoadInventory(force: Bool) async {
        let attemptedAt = clock.now()
        if !force, let lastInventoryAttemptAt {
            switch coordinatorConfiguration.refreshPolicy.mode {
            case .manual:
                return
            case .interval:
                if let interval = coordinatorConfiguration.refreshPolicy.intervalSeconds,
                   attemptedAt.timeIntervalSince(lastInventoryAttemptAt) < interval {
                    return
                }
            }
        }
        lastInventoryAttemptAt = attemptedAt
        isLoading = true
        defer { isLoading = false }
        let origins = originsForRefresh()
        guard !origins.isEmpty else {
            sourceStates = []
            capabilityStates = []
            inventory = .empty
            setLastError(
                title: "Inventory refresh failed",
                summary: "No coordinator state homes were found",
                details: "Set CODEX_AGENT_COORDINATOR_HOME or initialize a coordinator state home before refreshing.",
                source: "inventory"
            )
            logInventoryRefresh(states: sourceStates)
            return
        }
        let checkedAt = clock.now()
        let retainedSources = Dictionary(uniqueKeysWithValues: sourceStates.map { ($0.origin.id, $0) })
        let refreshingSources = origins.map { origin in
            if let retained = retainedSources[origin.id], retained.phase == .loaded || retained.phase == .stale {
                return retained
            }
            return CoordinatorSourceState(origin: origin, phase: .loading, checkedAt: checkedAt)
        }
        if refreshingSources != sourceStates { sourceStates = refreshingSources }
        let retainedOriginIDs = Set(
            refreshingSources.filter { $0.phase == .loaded || $0.phase == .stale }.map { $0.origin.id }
        )
        let retainedCapabilities = Dictionary(uniqueKeysWithValues: capabilityStates.map { ($0.id, $0) })
        let refreshingCapabilities = origins.flatMap { origin in
            CoordinatorCapability.allCases.map { capability in
                if retainedOriginIDs.contains(origin.id),
                   let retained = retainedCapabilities["\(origin.id)|\(capability.rawValue)"] {
                    return retained
                }
                return CoordinatorCapabilityState(
                    origin: origin,
                    capability: capability,
                    phase: .loading,
                    checkedAt: checkedAt,
                    error: nil
                )
            }
        }
        if refreshingCapabilities != capabilityStates { capabilityStates = refreshingCapabilities }
        let projectScope = scopedProjectPath
        let arguments = boardInventoryArguments + (projectScope.map { ["--project", $0] } ?? [])
        let observationMaxAgeSeconds: Double? = usesNormalizedAccountStore
            ? (force ? 0 : (coordinatorConfiguration.refreshPolicy.intervalSeconds
                ?? CoordinatorRefreshPolicy.defaultIntervalSeconds))
            : nil
        let service = coordinatorService
        let outcomes = await withTaskGroup(
            of: OriginInventoryLoadOutcome.self,
            returning: [OriginInventoryLoadOutcome].self
        ) { group in
            for (index, origin) in origins.enumerated() {
                group.addTask {
                    await loadOriginInventory(
                        index: index,
                        origin: origin,
                        arguments: arguments,
                        observationMaxAgeSeconds: observationMaxAgeSeconds,
                        coordinatorService: service
                    )
                }
            }
            var ordered = Array<OriginInventoryLoadOutcome?>(repeating: nil, count: origins.count)
            for await outcome in group {
                ordered[outcome.index] = outcome
            }
            return ordered.compactMap { $0 }
        }
        var states: [CoordinatorSourceState] = []
        var capabilities: [CoordinatorCapabilityState] = []
        var sourceFailures: [String] = []
        var observationFailures: [String] = []
        var capabilityFailures: [String] = []
        for outcome in outcomes {
            let origin = outcome.origin
            if let stage = outcome.failureStage {
                inventoryLogger.error(
                    "Inventory source load failed pid=\(Int(Darwin.getpid()), privacy: .public) stage=\(stage.rawValue, privacy: .public) exit_status=\(outcome.failureExitStatus ?? -999, privacy: .public) observation_failed=\(outcome.observationFailure != nil, privacy: .public)"
                )
            }
            var decoded: Inventory?
            var databaseWarning: String?
            var sourceFailure: String?
            switch outcome.result {
            case .success(let projection):
                decoded = projection.inventory
                normalizedCatalogByOrigin[origin.id] = projection.catalog
                if let repositoryTrees = projection.repositoryTrees {
                    normalizedRepositoryTreesByOrigin[origin.id] = repositoryTrees
                    originsWithAuthoritativeRepositoryTrees.insert(origin.id)
                } else {
                    normalizedRepositoryTreesByOrigin.removeValue(forKey: origin.id)
                    originsWithAuthoritativeRepositoryTrees.remove(origin.id)
                }
            case .failure(let failure):
                sourceFailure = failure
            }
            if var decoded {
                let sourcedOrigin = CoordinatorOrigin(label: origin.label, home: origin.home, statePath: decoded.statePath)
                let dockerError = decoded.docker.error?.trimmingCharacters(in: .whitespacesAndNewlines)
                let dockerFailureReason = dockerError.flatMap { $0.isEmpty ? nil : $0 } ?? "unknown Docker error"
                let dockerWarning: String? = decoded.docker.available == false || dockerError?.isEmpty == false
                    ? "Docker inventory unavailable: \(dockerFailureReason)"
                    : nil
                let databaseErrors = Array(
                    Set(decoded.postgres.compactMap(\.databaseDiscoveryError))
                ).sorted()
                databaseWarning = databaseErrors.isEmpty
                    ? nil
                    : "Database observation unavailable: \(databaseErrors.joined(separator: "; "))"
                if let dockerWarning {
                    let dependencyWarning = "Database capability unavailable because \(dockerWarning.lowercased())"
                    databaseWarning = [databaseWarning, dependencyWarning]
                        .compactMap { $0 }
                        .joined(separator: "; ")
                }
                decoded = attach(origin: sourcedOrigin, to: decoded)
                inventoryByOrigin[origin.id] = decoded
                let resourceCount = decoded.servers.count + decoded.leases.count + decoded.docker.containers.count + decoded.postgres.count
                states.append(
                    .init(
                        origin: sourcedOrigin,
                        phase: .loaded,
                        checkedAt: clock.now(),
                        resourceCount: resourceCount,
                        error: nil
                    )
                )
                capabilities.append(
                    .init(
                        origin: sourcedOrigin,
                        capability: .coordinator,
                        phase: .available,
                        checkedAt: clock.now(),
                        error: nil
                    )
                )
                capabilities.append(
                    .init(
                        origin: sourcedOrigin,
                        capability: .docker,
                        phase: dockerWarning == nil ? .available : .unavailable,
                        checkedAt: clock.now(),
                        error: dockerWarning
                    )
                )
                capabilities.append(
                    .init(
                        origin: sourcedOrigin,
                        capability: .database,
                        phase: databaseWarning == nil ? .available : .unavailable,
                        checkedAt: clock.now(),
                        error: databaseWarning
                    )
                )
                if let dockerWarning {
                    capabilityFailures.append("\(origin.label) (\(origin.home)) — Docker: \(dockerWarning)")
                }
                if let databaseWarning {
                    capabilityFailures.append("\(origin.label) (\(origin.home)) — Database: \(databaseWarning)")
                }
                if let observationFailure = outcome.observationFailure {
                    observationFailures.append(
                        "\(origin.label) (\(origin.home)): \(observationFailure)"
                    )
                }
            } else {
                let retained = inventoryByOrigin[origin.id]
                let phase: CoordinatorSourcePhase = retained == nil ? .failed : .stale
                let resourceCount = retained.map { $0.servers.count + $0.leases.count + $0.docker.containers.count + $0.postgres.count } ?? 0
                let inventoryFailure = sourceFailure ?? "Coordinator inventory unavailable"
                let failure = outcome.observationFailure.map {
                    "Inventory read failed: \(inventoryFailure). Live observation also failed: \($0)"
                } ?? inventoryFailure
                states.append(.init(origin: origin, phase: phase, checkedAt: clock.now(), resourceCount: resourceCount, error: failure))
                capabilities.append(contentsOf: CoordinatorCapability.allCases.map {
                    CoordinatorCapabilityState(
                        origin: origin,
                        capability: $0,
                        phase: .unavailable,
                        checkedAt: clock.now(),
                        error: "Coordinator inventory unavailable: \(failure)"
                    )
                })
                sourceFailures.append("\(origin.label) (\(origin.home)): \(failure)")
            }
        }
        sourceStates = states
        capabilityStates = capabilities
        if let selected = leaseOrigin {
            leaseOrigin = availableActionOrigins.first(where: { $0.id == selected.id }) ?? defaultActionOrigin
        }
        if let selected = startDraft.origin {
            startDraft.origin = availableActionOrigins.first(where: { $0.id == selected.id }) ?? defaultActionOrigin
        }
        let activeIDs = Set(origins.map(\.id))
        inventoryByOrigin = inventoryByOrigin.filter { activeIDs.contains($0.key) }
        normalizedCatalogByOrigin = normalizedCatalogByOrigin.filter { activeIDs.contains($0.key) }
        normalizedRepositoryTreesByOrigin = normalizedRepositoryTreesByOrigin.filter {
            activeIDs.contains($0.key)
        }
        originsWithAuthoritativeRepositoryTrees.formIntersection(activeIDs)
        let sourceInventories = origins.compactMap { origin -> RepositoryInventorySource? in
            guard let inventory = inventoryByOrigin[origin.id] else { return nil }
            return RepositoryInventorySource(origin: origin, inventory: inventory)
        }
        // Production has exactly one normalized per-account graph. Use its
        // durable repo_id and association projection directly.
        // The multi-origin branch exists only for injected migration fixtures;
        // it still derives from v2 projections, never from v1 compatibility.
        let catalog: RepositoryCatalog
        let repositoryTreeDefinitions: [NormalizedRepositoryTree]?
        if usesNormalizedAccountStore,
           origins.count == 1,
           let direct = normalizedCatalogByOrigin[origins[0].id]
        {
            catalog = direct
            repositoryTreeDefinitions = originsWithAuthoritativeRepositoryTrees.contains(origins[0].id)
                ? (normalizedRepositoryTreesByOrigin[origins[0].id] ?? [])
                : nil
        } else {
            catalog = RepositoryCatalog.build(from: sourceInventories)
            var treesByFamilyID: [String: NormalizedRepositoryTree] = [:]
            var contradictoryFamilies = Set<String>()
            for origin in origins {
                for tree in normalizedRepositoryTreesByOrigin[origin.id] ?? [] {
                    if let existing = treesByFamilyID[tree.familyID], existing != tree {
                        contradictoryFamilies.insert(tree.familyID)
                    } else {
                        treesByFamilyID[tree.familyID] = tree
                    }
                }
            }
            if !contradictoryFamilies.isEmpty {
                sourceFailures.append(
                    "Coordinator sources returned contradictory repository trees for: "
                        + contradictoryFamilies.sorted().joined(separator: ", ")
                )
                repositoryTreeDefinitions = []
            } else {
                let everyLoadedOriginHasTrees = sourceInventories.allSatisfy {
                    originsWithAuthoritativeRepositoryTrees.contains($0.origin.id)
                }
                repositoryTreeDefinitions = everyLoadedOriginHasTrees
                    ? treesByFamilyID.values.sorted {
                        ($0.rootRepository.displayName.lowercased(), $0.familyID)
                            < ($1.rootRepository.displayName.lowercased(), $1.familyID)
                    }
                    : nil
            }
        }
        var decoded = mergeInventories(sourceInventories.map(\.inventory))
        decoded.servers = deduplicatedManagedServers(decoded.servers)
        publishInventory(
            decoded,
            catalog: catalog,
            repositoryTreeDefinitions: repositoryTreeDefinitions
        )
        rebuildBackupRecords(from: decoded.backups)
        reconcileLeaseResults(now: clock.now())
        keepSelectionValid()
        if let selectedDatabase {
            requestBackupVerification(for: selectedDatabase)
        }
        if sourceFailures.isEmpty && observationFailures.isEmpty && capabilityFailures.isEmpty {
            if let configurationWarning {
                inventoryIssue = OpsIssue(
                    kind: .configuration,
                    title: "Coordinator configuration needs attention",
                    summary: configurationWarning,
                    details: configurationWarning,
                    createdAt: clock.now()
                )
                setLastError(
                    title: "Coordinator configuration needs attention",
                    summary: configurationWarning,
                    details: configurationWarning,
                    source: "configuration"
                )
            } else {
                inventoryIssue = nil
                if lastErrorSource == "inventory" || lastErrorSource == "configuration" { clearLegacyError() }
            }
        } else if !sourceFailures.isEmpty {
            let details = ([configurationWarning] + sourceFailures.map(Optional.some) + observationFailures.map(Optional.some) + capabilityFailures.map(Optional.some))
                .compactMap { $0 }
                .joined(separator: "\n")
            setLastError(
                title: "Inventory incomplete",
                summary: "\(sourceFailures.count) coordinator source\(sourceFailures.count == 1 ? "" : "s") could not be refreshed",
                details: details,
                source: "inventory"
            )
        } else if !observationFailures.isEmpty {
            let nextStep = "The Board loaded the last committed snapshot. Resolve the reported host observation error, then choose Refresh."
            let details = ([configurationWarning] + observationFailures.map(Optional.some) + capabilityFailures.map(Optional.some) + [nextStep])
                .compactMap { $0 }
                .joined(separator: "\n")
            setLastError(
                title: "Live inventory refresh unavailable",
                summary: "Showing the last committed inventory; live host observation failed",
                details: details,
                source: "inventory"
            )
        } else {
            let details = ([configurationWarning] + capabilityFailures.map(Optional.some))
                .compactMap { $0 }
                .joined(separator: "\n")
            setLastError(
                title: "Inventory degraded",
                summary: "\(capabilityFailures.count) coordinator capabilit\(capabilityFailures.count == 1 ? "y is" : "ies are") unavailable",
                details: details,
                source: "inventory"
            )
        }
        logInventoryRefresh(states: states)
    }

    private func logInventoryRefresh(states: [CoordinatorSourceState]) {
        let loadedStates = states.filter { $0.phase == .loaded }
        let loaded = loadedStates.count
        let total = states.count
        let pid = Int(Darwin.getpid())
        let sourceFingerprints = loadedStates
            .map { coordinatorSourceFingerprint($0.origin.id) }
            .sorted()
            .joined(separator: ",")
        let sourceEvidence = sourceFingerprints.isEmpty ? "none" : sourceFingerprints
        let disabledFingerprints = coordinatorConfiguration.sources
            .filter { !$0.enabled }
            .map { coordinatorSourceFingerprint($0.normalizedHome) }
            .sorted()
            .joined(separator: ",")
        let disabledEvidence = disabledFingerprints.isEmpty ? "none" : disabledFingerprints
        let serverCountEvidence = loadedStates
            .map { state in
                let fingerprint = coordinatorSourceFingerprint(state.origin.id)
                let count = inventoryByOrigin[state.origin.id]?.servers.count ?? 0
                return "\(fingerprint):\(count)"
            }
            .sorted()
            .joined(separator: ",")
        let serverCounts = serverCountEvidence.isEmpty ? "none" : serverCountEvidence
        let managedServers = presentedServers.count
        let visibleServers = filteredServers.count
        let canonicalRepositories = repositoryCatalog.repositories.count
        let repositoryGroups = projectGroups.filter(\.isRepository).count
        let unassignedGroups = projectGroups.filter { !$0.isRepository }.count
        let snapshot = presentationSnapshot
        let health: String
        switch snapshot.level {
        case .nominal: health = "nominal"
        case .busy: health = "busy"
        case .degraded: health = "degraded"
        case .unhealthy: health = "unhealthy"
        case .unavailable: health = "unavailable"
        }
        let attentionItems = snapshot.attentionItemCount
        let resolutionTargets = snapshot.resolutionTargetIDs.count
        let genericAttention = snapshot.statusTitle
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .localizedCaseInsensitiveCompare(
                snapshot.statusMessage.trimmingCharacters(in: .whitespacesAndNewlines)
            ) == .orderedSame ? "true" : "false"
        if loaded > 0 {
            inventoryLogger.info(
                "Inventory refresh completed pid=\(pid, privacy: .public) loaded=\(loaded, privacy: .public) total=\(total, privacy: .public) sources=\(sourceEvidence, privacy: .public) disabled=\(disabledEvidence, privacy: .public) server_counts=\(serverCounts, privacy: .public) managed=\(managedServers, privacy: .public) visible=\(visibleServers, privacy: .public) repositories=\(canonicalRepositories, privacy: .public) repository_groups=\(repositoryGroups, privacy: .public) unassigned_groups=\(unassignedGroups, privacy: .public) health=\(health, privacy: .public) attention_items=\(attentionItems, privacy: .public) resolution_targets=\(resolutionTargets, privacy: .public) generic_attention=\(genericAttention, privacy: .public)"
            )
        } else {
            inventoryLogger.error(
                "Inventory refresh failed pid=\(pid, privacy: .public) loaded=0 total=\(total, privacy: .public) sources=none disabled=\(disabledEvidence, privacy: .public) server_counts=none managed=\(managedServers, privacy: .public) visible=\(visibleServers, privacy: .public) repositories=\(canonicalRepositories, privacy: .public) repository_groups=\(repositoryGroups, privacy: .public) unassigned_groups=\(unassignedGroups, privacy: .public) health=\(health, privacy: .public) attention_items=\(attentionItems, privacy: .public) resolution_targets=\(resolutionTargets, privacy: .public) generic_attention=\(genericAttention, privacy: .public)"
            )
        }
    }

    private func coordinatorSourceFingerprint(_ normalizedHome: String) -> String {
        SHA256.hash(data: Data(normalizedHome.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private func attach(origin: CoordinatorOrigin, to inventory: Inventory) -> Inventory {
        var result = inventory
        result.origin = origin
        result.coordinatorHome = origin.home
        result.urls = result.urls.map { item in
            var item = item
            item.origin = origin
            return item
        }
        result.servers = result.servers.map { server in
            var server = server
            let nativeID = server.coordinatorID ?? server.id
            server.coordinatorID = nativeID
            server.origin = origin
            server.id = ResourceIdentity(origin: origin, kind: .server, nativeID: nativeID).rawValue
            return server
        }
        result.leases = result.leases.map { lease in
            var lease = lease
            let nativeID = lease.coordinatorID ?? lease.id
            lease.coordinatorID = nativeID
            lease.origin = origin
            lease.id = ResourceIdentity(origin: origin, kind: .lease, nativeID: nativeID).rawValue
            return lease
        }
        result.recentEvents = result.recentEvents.map { event in
            var event = event
            event.origin = origin
            return event
        }
        result.docker.containers = result.docker.containers.map { container in
            var container = container
            container.origin = origin
            return container
        }
        result.docker.postgres = result.docker.postgres.map { container in
            var container = container
            container.origin = origin
            return container
        }
        result.postgres = result.postgres.map { container in
            var container = container
            container.origin = origin
            return container
        }
        result.backups = result.backups.map { backup in
            var backup = backup
            backup.origin = origin
            return backup
        }
        result.projectUsage = result.projectUsage.map { usage in
            var usage = usage
            usage.origin = origin
            usage.processes = usage.processes?.map { process in
                var process = process
                process.origin = origin
                return process
            }
            return usage
        }
        result.testStatistics = result.testStatistics.map { statistics in
            var statistics = statistics
            statistics.origin = origin
            return statistics
        }
        return result
    }

    private func inventoryUsesCurrentSourcePresentation(_ inventory: Inventory) -> Bool {
        let currentOrigins = Dictionary(uniqueKeysWithValues: sourceStates.map { ($0.origin.id, $0.origin) })
        let representedOrigins = [inventory.origin]
            + inventory.urls.map(\.origin)
            + inventory.servers.map(\.origin)
            + inventory.leases.map(\.origin)
            + inventory.recentEvents.map(\.origin)
            + inventory.docker.containers.map(\.origin)
            + inventory.docker.postgres.map(\.origin)
            + inventory.postgres.map(\.origin)
            + inventory.backups.map(\.origin)
            + inventory.projectUsage.map(\.origin)
            + inventory.projectUsage.flatMap { $0.processes ?? [] }.map(\.origin)
            + inventory.testStatistics.map(\.origin)
        return representedOrigins.compactMap { $0 }.allSatisfy { represented in
            guard let current = currentOrigins[represented.id] else { return false }
            return represented.label == current.label
                && represented.home == current.home
                && represented.statePath == current.statePath
        }
    }

    private func mergeInventories(_ inventories: [Inventory]) -> Inventory {
        guard var first = inventories.first else { return .empty }
        first.coordinatorHome = inventories.compactMap(\.coordinatorHome).joined(separator: ", ")
        first.statePath = inventories.compactMap(\.statePath).joined(separator: ", ")
        first.urls = inventories.flatMap(\.urls)
        first.servers = inventories.flatMap(\.servers)
        first.leases = inventories.flatMap(\.leases)
        first.recentEvents = inventories.flatMap(\.recentEvents)
        first.docker = mergeDockerSummaries(inventories.map(\.docker))
        first.postgres = reconcileDockerAssociation(inventories.flatMap(\.postgres))
        first.backups = inventories.flatMap(\.backups)
        first.projectUsage = mergeProjectUsage(inventories.flatMap(\.projectUsage))
        first.testStatistics = inventories.flatMap(\.testStatistics)
        return first
    }

    private func reconcileLeaseResults(now: Date) {
        for lease in inventory.leases {
            guard let origin = lease.origin else { continue }
            let imported = LeaseActionResult(origin: origin, lease: lease, now: now)
            if leaseResults[imported.identity] == nil {
                leaseResults[imported.identity] = imported
            }
        }
        for identity in Array(leaseResults.keys) {
            guard var result = leaseResults[identity] else { continue }
            if let currentOrigin = sourceStates.first(where: {
                $0.origin.id == result.identity.origin.id
            })?.origin {
                result.rebind(origin: currentOrigin)
            }
            let lease = inventory.leases.first { item in
                item.origin?.id == result.identity.origin.id
                    && (item.coordinatorID ?? item.id) == result.leaseID
            }
            let phase = sourceStates.first { $0.origin.id == result.identity.origin.id }?.phase
            let isAuthoritativelyAbsent: Bool
            if let scope = scopedProjectPath {
                let scopedPath = URL(fileURLWithPath: scope).standardizedFileURL.path
                let leasePath = result.project.map { URL(fileURLWithPath: $0).standardizedFileURL.path }
                isAuthoritativelyAbsent = leasePath == scopedPath
            } else {
                isAuthoritativelyAbsent = true
            }
            result.reconcile(
                with: lease,
                sourcePhase: phase,
                isAuthoritativelyAbsent: isAuthoritativelyAbsent,
                now: now
            )
            leaseResults[identity] = result
        }
        if let identity = latestLeaseResult?.identity, let reconciled = leaseResults[identity] {
            latestLeaseResult = reconciled
        }
    }

    private func mergeDockerSummaries(_ summaries: [DockerSummary]) -> DockerSummary {
        let available = summaries.contains { $0.available == true } ? true : summaries.first?.available
        let error = summaries.compactMap(\.error).first
        let statsError = summaries.compactMap(\.statsError).first
        let containers = reconcileDockerAssociation(summaries.flatMap(\.containers))
        let postgres = reconcileDockerAssociation(summaries.flatMap(\.postgres))
        return DockerSummary(available: available, error: error, statsError: statsError, containers: containers, postgres: postgres)
    }

    private func reconcileDockerAssociation(_ containers: [DockerContainer]) -> [DockerContainer] {
        let grouped = Dictionary(grouping: containers) { container in
            container.id ?? "name:\(container.name ?? "unknown")"
        }
        return grouped.values.compactMap { bucket in
            // Normalized inventory already carries the coordinator's explicit
            // attribution decision. Do not erase its one account-scoped
            // action route merely because legacy sidecar/Compose labels are
            // absent; those labels are importer evidence, not the current association.
            let explicitlyAttributed = bucket.filter {
                $0.origin != nil
                    && $0.project?.isEmpty == false
                    && $0.associationError == nil
                    && $0.routeCandidates.count == 1
            }
            let explicitOrigins = Set(explicitlyAttributed.compactMap(\.origin))
            if explicitOrigins.count == 1,
               var selected = explicitlyAttributed.max(by: {
                   dockerContainerRank($0) < dockerContainerRank($1)
               })
            {
                selected.routeCandidates = Array(explicitOrigins)
                selected.associationError = nil
                return selected
            }
            // An unassigned normalized resource has no repository path by
            // definition, but it can still carry one exact observation identity and
            // immutable attach/retire evidence. Preserve that origin so the
            // corrective action remains available; do not reinterpret it as
            // a generic name-only Docker observation.
            let exactUnassigned = bucket.filter { container in
                guard container.origin != nil,
                      let attribution = container.attribution
                else { return false }
                return attribution.hostResourceID?.isEmpty == false
                    && attribution.immutableFingerprint?.isEmpty == false
                    && attribution.observationFingerprint?.isEmpty == false
                    && (attribution.canAttach || attribution.canRetire)
            }
            let exactUnassignedOrigins = Set(exactUnassigned.compactMap(\.origin))
            if exactUnassignedOrigins.count == 1,
               var selected = exactUnassigned.max(by: {
                   dockerContainerRank($0) < dockerContainerRank($1)
               })
            {
                selected.routeCandidates = Array(exactUnassignedOrigins)
                return selected
            }
            let sidecarOwners = Dictionary(
                grouping: bucket.filter {
                    $0.metadataSource == "coordinator_sidecar" && $0.project?.isEmpty == false && $0.origin != nil
                },
                by: { $0.origin!.id }
            )
            if sidecarOwners.count == 1, let owned = sidecarOwners.values.first {
                return owned.max(by: { dockerContainerRank($0) < dockerContainerRank($1) })
            }
            if sidecarOwners.count > 1 {
                guard var conflict = bucket.max(by: { dockerContainerRank($0) < dockerContainerRank($1) }) else { return nil }
                conflict.routeCandidates = sidecarOwners.values.compactMap { $0.first?.origin }.sorted { $0.id < $1.id }
                conflict.associationError = "conflicting coordinator-sidecar association"
                conflict.origin = nil
                return conflict
            }
            let composeOwned = bucket.filter {
                $0.metadataSource == "docker_labels" && $0.project?.isEmpty == false && $0.origin != nil
            }
            if let selected = composeOwned.sorted(by: { ($0.origin?.id ?? "") < ($1.origin?.id ?? "") }).first {
                var selected = selected
                selected.routeCandidates = composeOwned.compactMap(\.origin)
                return selected
            }
            guard var unknown = bucket.max(by: { dockerContainerRank($0) < dockerContainerRank($1) }) else { return nil }
            unknown.routeCandidates = bucket.compactMap(\.origin)
            unknown.associationError = "no coordinator or Docker Compose association metadata"
            unknown.origin = nil
            return unknown
        }
        .sorted { ($0.name ?? $0.stableID) < ($1.name ?? $1.stableID) }
    }

    private func dockerContainerRank(_ container: DockerContainer) -> (Int, Int, Int) {
        let metadataRank = (container.project?.isEmpty == false ? 2 : 0) + ((container.metadataSource ?? "none") == "none" ? 0 : 1)
        let statsRank = container.stats == nil ? 0 : 1
        let runningRank = container.isRunning ? 1 : 0
        return (metadataRank, statsRank, runningRank)
    }

    private func mergeProjectUsage(_ rows: [ProjectUsage]) -> [ProjectUsage] {
        let grouped = Dictionary(grouping: rows) { row in
            "\(row.origin?.id ?? "unknown")|\(row.usageKey ?? row.project ?? row.projectKey ?? row.name ?? "local")"
        }
        return grouped.values.map { bucket in
            var seenPIDs = Set<Int>()
            var processes: [ProcessUsage] = []
            var processCPU = 0.0
            var processMemory = 0.0
            var fallbackProcessCPU = 0.0
            var fallbackProcessMemory = 0.0
            var dockerCPU = 0.0
            var dockerMemory = 0.0
            var serverCount = 0
            var containerCount = 0
            // Association must merge as a union: each coordinator home only
            // reports the servers/containers it manages for the shared repo.
            var seenServerIDs = Set<String>()
            var serverIDs: [String] = []
            var seenContainerNames = Set<String>()
            var containerNames: [String] = []

            for row in bucket {
                serverCount += row.serverCount ?? 0
                containerCount = max(containerCount, row.containerCount ?? 0)
                dockerCPU = max(dockerCPU, row.dockerCPUPercent ?? 0)
                dockerMemory = max(dockerMemory, row.dockerMemoryBytes ?? 0)
                for serverID in row.serverIDs ?? [] where seenServerIDs.insert(serverID).inserted {
                    serverIDs.append(serverID)
                }
                for containerName in row.containerNames ?? [] where seenContainerNames.insert(containerName).inserted {
                    containerNames.append(containerName)
                }
                let rowProcesses = row.processes ?? []
                if rowProcesses.isEmpty {
                    fallbackProcessCPU += row.processCPUPercent ?? 0
                    fallbackProcessMemory += row.processMemoryBytes ?? 0
                }
                for process in rowProcesses {
                    guard let pid = process.pid, !seenPIDs.contains(pid) else { continue }
                    seenPIDs.insert(pid)
                    processes.append(process)
                    processCPU += process.cpuPercent ?? 0
                    processMemory += process.rssBytes ?? process.memoryBytes ?? 0
                }
            }

            if processes.isEmpty {
                processCPU = fallbackProcessCPU
                processMemory = fallbackProcessMemory
            }
            let first = bucket.max(by: { usageRank($0) < usageRank($1) }) ?? bucket[0]
            let hotProcesses = processes.sorted { ($0.cpuPercent ?? 0, $0.rssBytes ?? 0) > ($1.cpuPercent ?? 0, $1.rssBytes ?? 0) }.prefix(5).map { $0 }
            var merged = ProjectUsage(
                usageKey: first.usageKey,
                project: first.project,
                projectKey: first.projectKey,
                name: first.name,
                serverIDs: serverIDs.isEmpty ? nil : serverIDs,
                containerNames: containerNames.isEmpty ? nil : containerNames,
                serverCount: serverCount,
                containerCount: containerCount,
                processCount: processes.isEmpty ? first.processCount : processes.count,
                cpuPercent: processCPU + dockerCPU,
                memoryBytes: processMemory + dockerMemory,
                processCPUPercent: processCPU,
                processMemoryBytes: processMemory,
                dockerCPUPercent: dockerCPU,
                dockerMemoryBytes: dockerMemory,
                processes: processes,
                hotProcesses: hotProcesses.isEmpty ? first.hotProcesses : hotProcesses
            )
            merged.origin = first.origin
            return merged
        }
        .sorted { usageRank($0) > usageRank($1) }
    }

    func openURL(_ url: String?) {
        guard let raw = url, let url = URL(string: raw) else { return }
        NSWorkspace.shared.open(url)
    }

    func copyURL(_ url: String?) {
        guard let url else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(url, forType: .string)
    }

    func copyLastErrorDetails() {
        let detail = lastErrorDetails ?? lastError ?? ""
        guard !detail.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(detail, forType: .string)
    }

    func copyIssueDetails(_ issue: OpsIssue) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(issue.details, forType: .string)
    }

    func dismissActionIssue() {
        replaceActionIssue(with: nil)
        if lastErrorSource == "action" { clearLegacyError() }
    }

    func copyLeasePort(_ lease: LeaseActionResult) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(String(lease.port), forType: .string)
    }

    func dismissLatestLeaseResult() {
        latestLeaseResult = nil
    }

    func actionResultDetails(_ result: RetainedActionResult) -> String {
        actionResultDetails(result, formatPayloads: false)
    }

    func actionResultPresentationDetails(_ result: RetainedActionResult) -> String {
        actionResultDetails(result, formatPayloads: true)
    }

    private func actionResultDetails(
        _ result: RetainedActionResult,
        formatPayloads: Bool
    ) -> String {
        var lines = [
            "Action: \(result.request.title)",
            "Phase: \(result.phase.rawValue)",
            "Queued: \(ISO8601DateFormatter().string(from: result.queuedAt))",
        ]
        if let source = result.request.origin?.label { lines.append("Source: \(source)") }
        if let project = result.request.projectPath { lines.append("Project: \(project)") }
        if let startedAt = result.startedAt { lines.append("Started: \(ISO8601DateFormatter().string(from: startedAt))") }
        if let finishedAt = result.finishedAt { lines.append("Finished: \(ISO8601DateFormatter().string(from: finishedAt))") }
        if let exitStatus = result.exitStatus { lines.append("Exit status: \(exitStatus)") }
        if let failure = result.failure, !failure.isEmpty { lines.append("Failure: \(failure)") }
        if !result.stdout.isEmpty {
            let stdout = formatPayloads ? prettyPrintedJSONPayload(result.stdout) : result.stdout
            lines.append("Stdout:\n\(stdout)")
        }
        if !result.stderr.isEmpty {
            let stderr = formatPayloads ? prettyPrintedJSONPayload(result.stderr) : result.stderr
            lines.append("Stderr:\n\(stderr)")
        }
        if result.outputTruncated { lines.append("Output was truncated by the bounded executor.") }
        return lines.joined(separator: "\n")
    }

    private func prettyPrintedJSONPayload(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = trimmed.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              JSONSerialization.isValidJSONObject(object),
              let formatted = try? JSONSerialization.data(
                  withJSONObject: object,
                  options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
              )
        else { return value }
        return String(decoding: formatted, as: UTF8.self)
    }

    func copyActionResultDetails(
        _ result: RetainedActionResult,
        to pasteboard: NSPasteboard = .general
    ) {
        let detail = actionResultDetails(result)
        guard !detail.isEmpty else { return }
        pasteboard.clearContents()
        pasteboard.setString(detail, forType: .string)
    }

    var sortedActionResults: [RetainedActionResult] {
        actionResults.values.sorted { lhs, rhs in
            if lhs.queuedAt != rhs.queuedAt { return lhs.queuedAt > rhs.queuedAt }
            return lhs.id.uuidString < rhs.id.uuidString
        }
    }

    var visibleActivityActionResults: [RetainedActionResult] {
        sortedActionResults.filter { result in
            guard result.phase == .succeeded,
                  result.request.kind == .retireStandaloneResource
            else { return true }
            return !result.request.title.hasPrefix("Plan retirement of ")
        }
    }

    var selectedActionResult: RetainedActionResult? {
        if let selectedActionResultID, let selected = actionResults[selectedActionResultID] {
            return selected
        }
        return sortedActionResults.first
    }

    /// The retained action that owns the Activity workspace's current context.
    /// An unmatched issue is its own context and must not inherit an older
    /// selected action merely because one remains in retained history.
    var selectedActivityActionResult: RetainedActionResult? {
        guard selectedActivityIssueID == nil,
              let selectedActionResultID,
              let selected = actionResults[selectedActionResultID],
              visibleActivityActionResults.contains(where: { $0.id == selected.id })
        else { return nil }
        return selected
    }

    /// The issue that belongs to the Activity workspace's current selection.
    /// A newer global issue must not replace another selected action's header,
    /// details, or recovery control.
    var selectedActivityActionIssue: OpsIssue? {
        if let selectedActivityIssueID {
            return activityIssues.first { $0.id == selectedActivityIssueID }
        }
        guard let selectedActionResultID,
              let issue = activityIssues.first(where: {
                  $0.relatedActionID == selectedActionResultID
              })
        else { return nil }
        return issue
    }

    var activityIssues: [OpsIssue] {
        var issues: [OpsIssue] = []
        var seen = Set<UUID>()
        for issue in [actionIssue, inventoryIssue].compactMap({ $0 })
            where seen.insert(issue.id).inserted
        {
            issues.append(issue)
        }
        return issues
    }

    var selectedRetirementRecoveryContext: ResourceRetirementRecoveryContext? {
        guard let selectedActionResultID else { return nil }
        return retirementRecoveryContexts[selectedActionResultID]
    }

    var selectedRetirementRecoveryAction: ResourceRetirementRecoveryAction? {
        selectedRetirementRecoveryContext?.recoveryAction
    }

    var selectedRetirementRecoveryActionTitle: String? {
        switch selectedRetirementRecoveryAction {
        case .refreshAndReplan: return "Refresh & re-plan"
        case .retryConfirmedOperation: return "Retry confirmed operation"
        case nil: return nil
        }
    }

    /// Compatibility for the existing attention header. Recovery authority is
    /// action-scoped; an unrelated selected incident must never expose a target.
    var lastFailedRetirementTarget: ExactUnassignedResource? {
        guard selectedRetirementRecoveryAction != nil else { return nil }
        return selectedRetirementRecoveryContext?.prompt.target
    }

    func showActivity(actionID: UUID? = nil) {
        boardWorkspace = .activity
        if let actionID,
           visibleActivityActionResults.contains(where: { $0.id == actionID })
        {
            selectedActionResultID = actionID
            selectedActivityIssueID = nil
        } else if let issue = actionIssue,
                  issue.relatedActionID == nil
                    || issue.relatedActionID.flatMap({ actionResults[$0] }) == nil
        {
            selectedActivityIssueID = issue.id
            selectedActionResultID = nil
        } else if selectedActionResultID.flatMap({ selectedID in
            visibleActivityActionResults.first { $0.id == selectedID }
        }) == nil {
            if let result = visibleActivityActionResults.first {
                selectedActionResultID = result.id
                selectedActivityIssueID = nil
            } else if let issue = activityIssues.first {
                selectedActionResultID = nil
                selectedActivityIssueID = issue.id
            }
        }
    }

    func showActivity(issueID: UUID) {
        boardWorkspace = .activity
        guard let issue = activityIssues.first(where: { $0.id == issueID }) else { return }
        if let actionID = issue.relatedActionID, actionResults[actionID] != nil {
            selectedActionResultID = actionID
            selectedActivityIssueID = nil
        } else {
            selectedActionResultID = nil
            selectedActivityIssueID = issue.id
        }
    }

    func showResources() {
        boardWorkspace = .resources
    }

    func dismissActionResult(_ result: RetainedActionResult) {
        guard result.phase != .queued && result.phase != .running else { return }
        actionResults.removeValue(forKey: result.id)
        retirementRecoveryContexts.removeValue(forKey: result.id)
        if selectedActionResultID == result.id {
            if let next = visibleActivityActionResults.first {
                selectedActionResultID = next.id
                selectedActivityIssueID = nil
            } else if let issue = activityIssues.first(where: { $0.relatedActionID != result.id }) {
                selectedActionResultID = nil
                selectedActivityIssueID = issue.id
            } else {
                selectedActionResultID = nil
                selectedActivityIssueID = nil
            }
        }
        if actionIssue?.relatedActionID == result.id {
            clearActionErrorIfPresent(actionID: result.id)
        }
    }

    func clearLastError() {
        if lastErrorSource == "action" { replaceActionIssue(with: nil) }
        clearLegacyError()
    }

    private func clearLegacyError() {
        lastError = nil
        lastErrorDetails = nil
        lastErrorTitle = nil
        lastErrorSource = nil
    }

    private func clearActionErrorIfPresent(actionID: UUID) {
        guard actionIssue?.relatedActionID == actionID else { return }
        replaceActionIssue(with: nil)
        if lastErrorSource == "action" { clearLegacyError() }
    }

    private func replaceActionIssue(with replacement: OpsIssue?) {
        let replacingSelectedIssue: Bool
        if let currentIssue = actionIssue {
            replacingSelectedIssue = selectedActivityIssueID == currentIssue.id
        } else {
            replacingSelectedIssue = false
        }
        actionIssue = replacement
        guard replacingSelectedIssue else { return }

        if let replacement {
            if let actionID = replacement.relatedActionID,
               actionResults[actionID] != nil
            {
                selectedActionResultID = actionID
                selectedActivityIssueID = nil
            } else {
                selectedActionResultID = nil
                selectedActivityIssueID = replacement.id
            }
        } else {
            selectedActivityIssueID = nil
            if selectedActionResultID.flatMap({ selectedID in
                visibleActivityActionResults.first { $0.id == selectedID }
            }) == nil {
                selectedActionResultID = visibleActivityActionResults.first?.id
            }
        }
    }

    func selectProject(_ name: String) {
        selectedProjectName = name
        sidebarSelection = .project(name)
    }

    @discardableResult
    func reviewAttentionItem(_ item: ResourceAttentionItem) -> Bool {
        reviewAttentionTarget(item.reviewTarget)
    }

    @discardableResult
    func reviewAttentionTarget(_ target: AttentionReviewTarget) -> Bool {
        switch target.kind {
        case .server:
            guard let row = presentedServerRows.first(where: { $0.id == target.selectionID }) else {
                return reportUnavailableAttentionTarget(target)
            }
            selectServer(row.server)
        case .docker:
            guard let container = inventory.docker.containers.first(where: {
                $0.containerSelectionID == target.selectionID
            }) else {
                return reportUnavailableAttentionTarget(target)
            }
            selectDocker(container)
        case .project:
            guard projectGroups.contains(where: { $0.id == target.selectionID }) else {
                return reportUnavailableAttentionTarget(target)
            }
            selectProject(target.selectionID)
        }
        return true
    }

    private func reportUnavailableAttentionTarget(_ target: AttentionReviewTarget) -> Bool {
        setLastError(
            title: "Resource is no longer in the current inventory",
            summary: "Refresh inventory to review its latest state.",
            details: "The attention target \(target.stableID) changed or disappeared before it could be opened.",
            source: "action"
        )
        return false
    }

    func statusProject(_ group: ProjectGroup) {
        runProjectRuntime("status", group: group)
    }

    func startProject(_ group: ProjectGroup) {
        runProjectRuntime("start", group: group)
    }

    func restartProject(_ group: ProjectGroup) {
        runProjectRuntime("restart", group: group)
    }

    func stopProject(_ group: ProjectGroup) {
        runProjectRuntime("stop", group: group)
    }

    func planRepositoryDecommission(_ group: ProjectGroup) {
        guard group.isRepository,
              let projectPath = group.projectPath?.trimmingCharacters(in: .whitespacesAndNewlines),
              !projectPath.isEmpty
        else {
            setLastError(
                title: "Repository removal unavailable",
                summary: "This selection is not a validated repository",
                details: "Only one canonical local Git repository can be removed through this action.",
                source: "action"
            )
            return
        }
        guard let origin = group.actionOrigin else {
            setLastError(
                title: "Repository removal unavailable",
                summary: "No authoritative coordinator controls this repository",
                details: "Resolve the repository's routing identity before planning removal.",
                source: "action"
            )
            return
        }
        let identity = ResourceIdentity(origin: origin, kind: .project, nativeID: projectPath)
        guard requireMutationAvailability(
            title: "Plan removal of \(group.name)",
            kind: .repositoryDecommissionPlan,
            origin: origin,
            resource: identity,
            projectPath: projectPath
        ) else { return }
        let request = beginAction(
            kind: .repositoryDecommissionPlan,
            title: "Plan removal of \(group.name)",
            origin: origin,
            resource: identity,
            projectPath: projectPath
        )
        Task {
            markActionRunning(request.id)
            let arguments = [
                "repository", "plan-remove",
                "--project", projectPath,
                "--agent", agentID,
                "--reason", "Removed from DevOps Board",
            ]
            do {
                let result = try await coordinatorService.execute(origin: origin, arguments: arguments)
                guard result.exitStatus == 0 else {
                    failAction(request.id, execution: result, failure: commandFailureMessage(result))
                    setCommandFailure(
                        title: "Plan removal of \(group.name)",
                        command: ["python3", "<coordinator>"] + arguments,
                        result: result,
                        actionID: request.id
                    )
                    return
                }
                let plan = try JSONDecoder().decode(
                    RepositoryDecommissionPlan.self,
                    from: Data(result.stdout.utf8)
                )
                guard plan.kind == "repository_decommission",
                      group.repositoryID == nil || plan.repoID == group.repositoryID,
                      plan.canonicalRoot == nil
                        || URL(fileURLWithPath: plan.canonicalRoot!).standardizedFileURL.path
                            == URL(fileURLWithPath: projectPath).standardizedFileURL.path
                else {
                    throw RuntimeError("Coordinator returned a removal plan for a different repository")
                }
                repositoryDecommissionPrompt = RepositoryDecommissionPrompt(
                    plan: plan,
                    origin: origin,
                    projectPath: projectPath,
                    repositoryID: group.repositoryID
                )
                finishAction(request.id, execution: result)
                clearActionErrorIfPresent(actionID: request.id)
            } catch {
                failAction(request.id, error: error)
                setLastError(
                    title: "Removal plan unavailable",
                    summary: error.localizedDescription,
                    details: commandFailureDetails(
                        title: "Plan removal of \(group.name)",
                        command: ["python3", "<coordinator>"] + arguments,
                        result: nil,
                        thrownError: error
                    ),
                    source: "action",
                    actionID: request.id
                )
            }
        }
    }

    func cancelRepositoryDecommission() {
        repositoryDecommissionPrompt = nil
    }

    func applyRepositoryDecommission(_ prompt: RepositoryDecommissionPrompt) {
        let identity = ResourceIdentity(
            origin: prompt.origin,
            kind: .project,
            nativeID: prompt.repositoryID ?? prompt.projectPath
        )
        guard requireMutationAvailability(
            title: "Remove \(prompt.plan.displayName ?? prompt.projectPath)",
            kind: .repositoryDecommission,
            origin: prompt.origin,
            resource: identity,
            projectPath: prompt.projectPath
        ) else {
            repositoryDecommissionPrompt = nil
            showActivity()
            return
        }
        let request = beginAction(
            kind: .repositoryDecommission,
            title: "Remove \(prompt.plan.displayName ?? prompt.projectPath)",
            origin: prompt.origin,
            resource: identity,
            projectPath: prompt.projectPath
        )
        repositoryDecommissionPrompt = nil
        showActivity(actionID: request.id)
        Task {
            markActionRunning(request.id)
            let arguments = [
                "repository", "remove",
                "--project", prompt.projectPath,
                "--agent", agentID,
                "--plan-id", prompt.plan.planID,
                "--plan-fingerprint", prompt.plan.fingerprint,
            ]
            do {
                let execution = try await coordinatorService.execute(
                    origin: prompt.origin,
                    arguments: arguments
                )
                guard execution.exitStatus == 0 else {
                    failAction(request.id, execution: execution, failure: commandFailureMessage(execution))
                    setCommandFailure(
                        title: "Remove \(prompt.plan.displayName ?? prompt.projectPath)",
                        command: ["python3", "<coordinator>"] + arguments,
                        result: execution,
                        actionID: request.id
                    )
                    return
                }
                let result = try JSONDecoder().decode(
                    RepositoryLifecycleResult.self,
                    from: Data(execution.stdout.utf8)
                )
                guard result.status == "succeeded" || result.status == "already_complete" else {
                    let failures = result.errors.map(\.message)
                        + result.targets.compactMap { $0.error?.message }
                    throw RuntimeError(
                        failures.isEmpty
                            ? "Repository removal needs attention"
                            : failures.joined(separator: "\n")
                    )
                }
                guard prompt.repositoryID == nil || result.repoID == prompt.repositoryID else {
                    throw RuntimeError("Coordinator returned a removal result for a different repository")
                }
                guard result.hidden, !result.started else {
                    throw RuntimeError(
                        "Coordinator did not prove the repository hidden and stopped after removal"
                    )
                }
                finishAction(request.id, execution: execution)
                clearActionErrorIfPresent(actionID: request.id)
                await loadInventory(force: true)
            } catch {
                failAction(request.id, error: error)
                setLastError(
                    title: "Repository removal needs attention",
                    summary: error.localizedDescription,
                    details: "The coordinator keeps the start fence after a partial removal. Review the retained per-target action result, then retry the same removal safely.",
                    source: "action",
                    actionID: request.id
                )
                await loadInventory(force: true)
            }
        }
    }

    var attachableRepositoryGroups: [ProjectGroup] {
        projectGroups
            .filter { group in
                group.isRepository
                    && group.projectPath?.isEmpty == false
                    && group.actionOrigin != nil
                    && !group.projectActionsBlocked
            }
            .sorted { ($0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending) }
    }

    func prepareResourceAttach(_ target: ExactUnassignedResource) {
        guard !attachableRepositoryGroups.isEmpty else {
            setLastError(
                title: "Resource attachment unavailable",
                summary: "No installed repository is ready to receive this resource",
                details: "Install the destination repository with the Coordinator skill, refresh inventory, then explicitly attach this exact resource.",
                source: "action"
            )
            return
        }
        resourceAttachPrompt = ResourceAttachPrompt(target: target)
    }

    func cancelResourceAttach() {
        resourceAttachPrompt = nil
    }

    func attachResource(_ prompt: ResourceAttachPrompt, to group: ProjectGroup) {
        guard let projectPath = group.projectPath,
              let actionOrigin = group.actionOrigin,
              actionOrigin.id == prompt.target.origin.id
        else {
            setLastError(
                title: "Resource attachment unavailable",
                summary: "The destination repository has no matching command route",
                details: "Choose an installed repository available through the same normalized Coordinator endpoint.",
                source: "action"
            )
            return
        }
        let identity = resourceIdentity(for: prompt.target)
        guard requireMutationAvailability(
            title: "Attach \(prompt.target.displayName)",
            kind: .attachResource,
            origin: prompt.target.origin,
            resource: identity,
            projectPath: projectPath
        ) else { return }
        let request = beginAction(
            kind: .attachResource,
            title: "Attach \(prompt.target.displayName) to \(group.name)",
            origin: prompt.target.origin,
            resource: identity,
            projectPath: projectPath
        )
        resourceAttachPrompt = nil
        showActivity(actionID: request.id)
        Task {
            markActionRunning(request.id)
            let arguments = ["resource", "attach"]
                + prompt.target.identityArguments
                + [
                    "--project", projectPath,
                    "--agent", agentID,
                    "--reason", "Attached from DevOps Board",
                ]
            do {
                let execution = try await coordinatorService.execute(
                    origin: prompt.target.origin,
                    arguments: arguments
                )
                guard execution.exitStatus == 0 else {
                    failAction(request.id, execution: execution, failure: commandFailureMessage(execution))
                    setCommandFailure(
                        title: "Attach \(prompt.target.displayName)",
                        command: ["python3", "<coordinator>"] + arguments,
                        result: execution,
                        actionID: request.id
                    )
                    await loadInventory(force: true)
                    return
                }
                let result = try JSONDecoder().decode(
                    ResourceAttachResult.self,
                    from: Data(execution.stdout.utf8)
                )
                guard result.attached,
                      !result.started,
                      result.resourceID == prompt.target.hostResourceID,
                      group.repositoryID == nil || result.repoID == group.repositoryID
                else {
                    throw RuntimeError("Coordinator did not prove this exact resource attached without starting it")
                }
                finishAction(request.id, execution: execution)
                clearActionErrorIfPresent(actionID: request.id)
                await loadInventory(force: true)
            } catch {
                failAction(request.id, error: error)
                setLastError(
                    title: "Resource attachment failed",
                    summary: error.localizedDescription,
                    details: "The resource remains unassigned unless the refreshed coordinator inventory proves the exact attachment.",
                    source: "action",
                    actionID: request.id
                )
                await loadInventory(force: true)
            }
        }
    }

    func planResourceRetirement(
        _ target: ExactUnassignedResource,
        replacingRecoveryActionID: UUID? = nil
    ) {
        let identity = resourceIdentity(for: target)
        guard requireMutationAvailability(
            title: "Plan retirement of \(target.displayName)",
            kind: .retireStandaloneResource,
            origin: target.origin,
            resource: identity
        ) else { return }
        let request = beginAction(
            kind: .retireStandaloneResource,
            title: "Plan retirement of \(target.displayName)",
            origin: target.origin,
            resource: identity
        )
        Task {
            markActionRunning(request.id)
            do {
                guard let requestProject = try await coordinatorService.requestProjectRoot() else {
                    throw RuntimeError("Coordinator request-project provenance is unavailable")
                }
                let arguments = ["resource", "plan-retire"]
                    + target.identityArguments
                    + [
                        "--request-project", requestProject,
                        "--agent", agentID,
                        "--reason", "Retired from DevOps Board",
                    ]
                let execution = try await coordinatorService.execute(
                    origin: target.origin,
                    arguments: arguments
                )
                guard execution.exitStatus == 0 else {
                    failAction(request.id, execution: execution, failure: commandFailureMessage(execution))
                    setCommandFailure(
                        title: "Plan retirement of \(target.displayName)",
                        command: ["python3", "<coordinator>"] + arguments,
                        result: execution,
                        actionID: request.id
                    )
                    return
                }
                let plan = try JSONDecoder().decode(
                    StandaloneRetirementPlan.self,
                    from: Data(execution.stdout.utf8)
                )
                guard hasSemanticLifecycleIdentity(plan.planID),
                      hasSemanticLifecycleIdentity(plan.fingerprint),
                      hasSemanticLifecycleIdentity(plan.resourceID),
                      plan.kind == "standalone_resource_retirement",
                      plan.resourceID == target.hostResourceID,
                      plan.targets.count == 1,
                      hasSemanticLifecycleIdentity(plan.targets[0].targetID),
                      hasSemanticLifecycleIdentity(plan.targets[0].hostResourceID),
                      hasSemanticLifecycleIdentity(plan.targets[0].immutableFingerprint),
                      plan.targets[0].targetID == target.hostResourceID,
                      plan.targets[0].hostResourceID == target.hostResourceID,
                      plan.targets[0].kind == target.kind,
                      plan.targets[0].immutableFingerprint == target.immutableFingerprint,
                      plan.targets[0].stableIdentityFingerprint?
                        .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false,
                      plan.targets[0].identityArguments != nil
                else {
                    throw RuntimeError("Coordinator returned a retirement plan without the exact refreshed resource identity")
                }
                resourceRetirementPrompt = ResourceRetirementPrompt(
                    target: target,
                    plan: plan,
                    requestProject: requestProject
                )
                if let replacingRecoveryActionID {
                    retirementRecoveryContexts.removeValue(forKey: replacingRecoveryActionID)
                }
                finishAction(request.id, execution: execution)
                clearActionErrorIfPresent(actionID: request.id)
            } catch {
                failAction(request.id, error: error)
                setLastError(
                    title: "Resource retirement plan unavailable",
                    summary: error.localizedDescription,
                    details: "No resource was changed. Refresh the exact host observation and try again.",
                    source: "action",
                    actionID: request.id
                )
            }
        }
    }

    func cancelResourceRetirement() {
        resourceRetirementPrompt = nil
    }

    func applyResourceRetirement(
        _ prompt: ResourceRetirementPrompt,
        recoveringActionID: UUID? = nil
    ) {
        let identity = resourceIdentity(for: prompt.target)
        guard requireMutationAvailability(
            title: "Retire \(prompt.target.displayName)",
            kind: .retireStandaloneResource,
            origin: prompt.target.origin,
            resource: identity
        ) else {
            resourceRetirementPrompt = nil
            showActivity()
            return
        }
        guard hasSemanticLifecycleIdentity(prompt.plan.planID),
              hasSemanticLifecycleIdentity(prompt.plan.fingerprint),
              hasSemanticLifecycleIdentity(prompt.plan.resourceID),
              let plannedTarget = prompt.plan.targets.first,
              hasSemanticLifecycleIdentity(plannedTarget.targetID),
              hasSemanticLifecycleIdentity(plannedTarget.hostResourceID),
              hasSemanticLifecycleIdentity(plannedTarget.immutableFingerprint),
              plannedTarget.targetID == prompt.target.hostResourceID,
              plannedTarget.hostResourceID == prompt.target.hostResourceID,
              plannedTarget.kind == prompt.target.kind,
              plannedTarget.immutableFingerprint == prompt.target.immutableFingerprint,
              plannedTarget.stableIdentityFingerprint?
                .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false,
              let plannedIdentityArguments = plannedTarget.identityArguments
        else {
            resourceRetirementPrompt = nil
            setLastError(
                title: "Resource retirement plan is incomplete",
                summary: "The confirmed plan does not contain the refreshed exact resource identity.",
                details: "No resource was changed. Refresh and create a new retirement plan with the current Coordinator.",
                source: "action"
            )
            showActivity()
            return
        }
        let request = beginAction(
            kind: .retireStandaloneResource,
            title: "Retire \(prompt.target.displayName)",
            origin: prompt.target.origin,
            resource: identity
        )
        resourceRetirementPrompt = nil
        clearRetirementRecoveryContexts(for: prompt)
        showActivity(actionID: request.id)
        Task {
            markActionRunning(request.id)
            let arguments = ["resource", "retire"]
                + plannedIdentityArguments
                + [
                    "--request-project", prompt.requestProject,
                    "--agent", agentID,
                    "--plan-id", prompt.plan.planID,
                    "--plan-fingerprint", prompt.plan.fingerprint,
                ]
            var retainedExecution: CommandExecution?
            do {
                let execution = try await coordinatorService.execute(
                    origin: prompt.target.origin,
                    arguments: arguments
                )
                retainedExecution = execution
                guard execution.exitStatus == 0 else {
                    let commandFailure = lifecycleCommandFailure(from: execution)
                    let failure = commandFailure?.error ?? commandFailureMessage(execution)
                    failAction(request.id, execution: execution, failure: failure)
                    retainRetirementRecovery(
                        actionID: request.id,
                        prompt: prompt,
                        recoveryAction: {
                            if commandFailure?.isPreMutationStalePlan == true {
                                return .refreshAndReplan
                            }
                            if commandFailure?.isFencedResumeFailure == true {
                                return .retryConfirmedOperation
                            }
                            return nil
                        }(),
                        commandFailure: commandFailure
                    )
                    setLastError(
                        title: "Retire \(prompt.target.displayName) failed",
                        summary: failure,
                        details: retirementCommandFailureDetails(
                            title: "Retire \(prompt.target.displayName)",
                            command: ["python3", "<coordinator>"] + arguments,
                            execution: execution,
                            failure: commandFailure
                        ),
                        source: "action",
                        actionID: request.id
                    )
                    await loadInventory(force: true)
                    return
                }
                let result = try JSONDecoder().decode(
                    RepositoryLifecycleResult.self,
                    from: Data(execution.stdout.utf8)
                )
                if let contractFailure = retirementResultContractFailure(
                    result,
                    prompt: prompt
                ) {
                    throw RuntimeError(contractFailure)
                }
                if result.status == "needs_attention" {
                    guard retirementResultIsCoherentNeedsAttention(result) else {
                        throw RuntimeError(
                            "Coordinator did not return coherent retry evidence for the confirmed retirement"
                        )
                    }
                    let failures = result.errors.map(\.message)
                        + result.targets.compactMap { $0.error?.message }
                    let failure = failures.isEmpty
                        ? "Coordinator did not prove this exact resource retired and hidden"
                        : failures.joined(separator: "\n")
                    failAction(request.id, execution: execution, failure: failure)
                    retainRetirementRecovery(
                        actionID: request.id,
                        prompt: prompt,
                        recoveryAction: .retryConfirmedOperation,
                        resultStatus: result.status
                    )
                    setLastError(
                        title: "Retire \(prompt.target.displayName) needs attention",
                        summary: failure,
                        details: "The confirmed operation is fenced and its evidence is retained in Activity. Retry this exact confirmed plan; do not create a replacement plan.",
                        source: "action",
                        actionID: request.id
                    )
                    await loadInventory(force: true)
                    return
                }
                guard retirementResultIsCoherentSuccess(result) else {
                    throw RuntimeError(
                        "Coordinator did not return coherent terminal evidence for this exact retirement"
                    )
                }
                clearRetirementRecoveryContexts(for: prompt)
                finishAction(request.id, execution: execution)
                if let recoveringActionID {
                    clearActionErrorIfPresent(actionID: recoveringActionID)
                }
                clearActionErrorIfPresent(actionID: request.id)
                await loadInventory(force: true)
            } catch {
                failAction(
                    request.id,
                    execution: retainedExecution,
                    failure: error.localizedDescription,
                    error: error
                )
                retainRetirementRecovery(
                    actionID: request.id,
                    prompt: prompt,
                    recoveryAction: nil
                )
                setLastError(
                    title: "Resource retirement needs attention",
                    summary: error.localizedDescription,
                    details: "The response could not be proved to belong to the confirmed retirement plan. Review the retained Activity evidence before taking another action.",
                    source: "action",
                    actionID: request.id
                )
                await loadInventory(force: true)
            }
        }
    }

    func refreshAndReplanFailedRetirement() {
        guard let recovery = selectedRetirementRecoveryContext,
              let recoveryAction = recovery.recoveryAction
        else {
            refresh()
            return
        }
        if recoveryAction == .retryConfirmedOperation {
            applyResourceRetirement(
                recovery.prompt,
                recoveringActionID: recovery.actionID
            )
            return
        }
        let failedTarget = recovery.prompt.target
        Task {
            await loadInventory(force: true)
            guard let refreshedTarget = refreshedUnassignedResource(matching: failedTarget) else {
                retirementRecoveryContexts.removeValue(forKey: recovery.actionID)
                setLastError(
                    title: "Retirement target is no longer available",
                    summary: "The refreshed inventory no longer contains this standalone resource.",
                    details: "It may already be retired or assigned to a repository. Review Resources before taking another action.",
                    source: "action"
                )
                showResources()
                return
            }
            dismissActionIssue()
            showResources()
            planResourceRetirement(
                refreshedTarget,
                replacingRecoveryActionID: recovery.actionID
            )
        }
    }

    func recoverSelectedRetirement() {
        refreshAndReplanFailedRetirement()
    }

    private func refreshedUnassignedResource(
        matching target: ExactUnassignedResource
    ) -> ExactUnassignedResource? {
        if target.kind == "server" {
            return repositoryCatalog.unassigned.servers
                .compactMap { $0.server.exactUnassignedResource }
                .first {
                    $0.origin.id == target.origin.id
                        && $0.hostResourceID == target.hostResourceID
                }
        }
        return repositoryCatalog.unassigned.docker
            .compactMap { $0.representative.exactUnassignedResource }
            .first {
                $0.origin.id == target.origin.id
                    && $0.hostResourceID == target.hostResourceID
            }
    }

    private func lifecycleCommandFailure(
        from execution: CommandExecution
    ) -> LifecycleCommandFailurePayload? {
        for output in [execution.stderr, execution.stdout] {
            let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  let data = trimmed.data(using: .utf8),
                  let payload = try? JSONDecoder().decode(
                    LifecycleCommandFailurePayload.self,
                    from: data
                  )
            else { continue }
            return payload
        }
        return nil
    }

    private func hasSemanticLifecycleIdentity(_ value: String?) -> Bool {
        guard let value else { return false }
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func retirementCommandFailureDetails(
        title: String,
        command: [String],
        execution: CommandExecution,
        failure: LifecycleCommandFailurePayload?
    ) -> String {
        var sections: [String] = []
        if let actionRequired = failure?.actionRequired?.trimmingCharacters(
            in: .whitespacesAndNewlines
        ),
           !actionRequired.isEmpty
        {
            sections.append(actionRequired)
        }
        if failure?.priorOperationEffectsPossible == true,
           failure?.mutationPerformed == false
        {
            sections.append(
                "This retry performed no additional host mutation; the original fenced operation may already have retained host effects."
            )
        } else if failure?.priorOperationEffectsPossible == true {
            sections.append(
                "The confirmed operation remains fenced and may already have host effects. Inspect the retained evidence before retrying the exact operation."
            )
        } else if failure?.mutationPerformed == false {
            sections.append("The rejected call performed no host mutation.")
        }
        sections.append(
            commandFailureDetails(
                title: title,
                command: command,
                result: execution,
                thrownError: nil
            )
        )
        return sections.joined(separator: "\n\n")
    }

    private func retirementResultContractFailure(
        _ result: RepositoryLifecycleResult,
        prompt: ResourceRetirementPrompt
    ) -> String? {
        guard hasSemanticLifecycleIdentity(result.operationID),
              hasSemanticLifecycleIdentity(result.planID),
              hasSemanticLifecycleIdentity(result.planFingerprint)
        else {
            return "Coordinator returned blank retirement operation or execution-plan identity"
        }
        guard result.kind == "standalone_resource_retirement" else {
            return "Coordinator returned a different lifecycle operation kind"
        }
        guard result.resourceID == prompt.target.hostResourceID else {
            return "Coordinator returned retirement evidence for another host resource"
        }
        guard let confirmed = result.confirmedPlan,
              hasSemanticLifecycleIdentity(confirmed.planID),
              hasSemanticLifecycleIdentity(confirmed.planFingerprint),
              confirmed.planID == prompt.plan.planID,
              confirmed.planFingerprint == prompt.plan.fingerprint
        else {
            return "Coordinator did not bind the result to the confirmed retirement plan"
        }
        guard let execution = result.executionPlan,
              hasSemanticLifecycleIdentity(execution.planID),
              hasSemanticLifecycleIdentity(execution.planFingerprint),
              execution.planID == result.planID,
              execution.planFingerprint == result.planFingerprint
        else {
            return "Coordinator returned inconsistent retirement execution-plan evidence"
        }
        guard result.targets.count == 1,
              result.targets[0].targetID == prompt.target.hostResourceID,
              result.targets[0].kind == prompt.target.kind
        else {
            return "Coordinator returned retirement target evidence for another resource"
        }
        return nil
    }

    private func retirementResultIsCoherentSuccess(
        _ result: RepositoryLifecycleResult
    ) -> Bool {
        guard result.status == "succeeded" || result.status == "already_complete",
              result.fence == "disabled",
              result.hidden,
              !result.started,
              result.errors.isEmpty,
              result.targets.count == 1
        else { return false }
        let target = result.targets[0]
        return target.status == "succeeded"
            && target.phase == "complete"
            && target.error == nil
    }

    private func retirementResultIsCoherentNeedsAttention(
        _ result: RepositoryLifecycleResult
    ) -> Bool {
        guard result.status == "needs_attention",
              result.fence == "retained",
              !result.hidden,
              !result.started,
              result.targets.count == 1
        else { return false }
        let target = result.targets[0]
        return target.status == "failed"
            && target.phase != "complete"
            && (target.error != nil || !result.errors.isEmpty)
    }

    private func retainRetirementRecovery(
        actionID: UUID,
        prompt: ResourceRetirementPrompt,
        recoveryAction: ResourceRetirementRecoveryAction?,
        commandFailure: LifecycleCommandFailurePayload? = nil,
        resultStatus: String? = nil
    ) {
        retirementRecoveryContexts[actionID] = ResourceRetirementRecoveryContext(
            actionID: actionID,
            prompt: prompt,
            recoveryAction: recoveryAction,
            commandFailure: commandFailure,
            resultStatus: resultStatus
        )
    }

    private func clearRetirementRecoveryContexts(
        for prompt: ResourceRetirementPrompt
    ) {
        retirementRecoveryContexts = retirementRecoveryContexts.filter { entry in
            let context = entry.value
            return context.prompt.target.origin.id != prompt.target.origin.id
                || context.prompt.plan.planID != prompt.plan.planID
        }
    }

    private func resourceIdentity(for target: ExactUnassignedResource) -> ResourceIdentity {
        ResourceIdentity(
            origin: target.origin,
            kind: target.kind == "server" ? .server : .docker,
            nativeID: target.hostResourceID
        )
    }

    func selectServer(_ server: ManagedServer) {
        activeTab = .servers
        let selectionID = serverSelectionID(for: server)
        selectedServerID = selectionID
        sidebarSelection = .server(selectionID)
    }

    func selectDocker(_ container: DockerContainer) {
        activeTab = .docker
        selectedDockerID = container.containerSelectionID
        sidebarSelection = .docker(container.containerSelectionID)
    }

    func selectDatabase(_ container: DockerContainer) {
        activeTab = .databases
        selectedDatabaseID = container.databaseSelectionID
        sidebarSelection = .database(container.databaseSelectionID)
        requestBackupVerification(for: container)
    }

    func repositoryExecutionContext(for server: ManagedServer) -> RepositoryExecutionContext? {
        let serverID = server.coordinatorID ?? server.id
        let matches = repositoryTrees.flatMap { tree in
            tree.scopes.compactMap { scope in
                scope.definition.serverIDs.contains(serverID) ? scope.context : nil
            }
        }
        return matches.count == 1 ? matches[0] : nil
    }

    private func workerRuntimeArguments(
        action: String,
        serverID: String,
        serverName: String,
        context: RepositoryExecutionContext,
        keepAlive: Bool? = nil,
        rearmCrashLoop: Bool? = nil,
        removalPlan: WorkerRemovalPlan? = nil
    ) -> [String] {
        var arguments = [
            "runtime", action,
            "--agent", agentID,
            "--root-repo", context.rootCanonicalRoot,
        ]
        if context.projectKind == .temporary {
            arguments.append(contentsOf: ["--temporary-repo", context.effectiveCanonicalRoot])
        } else {
            arguments.append("--no-temporary-repo")
        }
        arguments.append(contentsOf: [
            "--target-kind", "service",
            "--target-id", serverID,
            "--target-name", serverName,
            "--purpose", "development",
            "--no-ttl",
            "--kill-after-run", "false",
            "--reason", "Worker lifecycle requested from DevOps Board",
        ])
        if let keepAlive {
            arguments.append(contentsOf: ["--keep-alive", keepAlive ? "true" : "false"])
        }
        if let rearmCrashLoop {
            arguments.append(contentsOf: ["--rearm-crash-loop", rearmCrashLoop ? "true" : "false"])
        }
        if let removalPlan {
            arguments.append(contentsOf: [
                "--remove-plan-id", removalPlan.planID,
                "--remove-plan-fingerprint", removalPlan.planFingerprint,
                "--remove-confirmation-phrase", removalPlan.confirmationPhrase,
            ])
        }
        return arguments
    }

    private func validateWorkerRuntimeEnvelope(
        _ execution: CommandExecution,
        serverID: String,
        action: String
    ) throws -> WorkerRuntimeEnvelope {
        let envelope = try JSONDecoder().decode(
            WorkerRuntimeEnvelope.self,
            from: Data(execution.stdout.utf8)
        )
        guard envelope.schemaVersion == 1,
              envelope.action == action,
              envelope.target.kind == "service",
              envelope.target.id == serverID
        else {
            throw RuntimeError("Coordinator returned a worker result for a different target")
        }
        return envelope
    }

    private func runWorkerRuntime(
        _ action: String,
        server: ManagedServer,
        kind: ActionKind,
        title: String,
        keepAlive: Bool? = nil,
        rearmCrashLoop: Bool? = nil
    ) {
        guard server.supervision != nil,
              let origin = server.origin,
              let identity = server.resourceIdentity,
              let context = repositoryExecutionContext(for: server)
        else {
            reportMissingAssociation(title)
            return
        }
        let serverID = server.coordinatorID ?? server.id
        let arguments = workerRuntimeArguments(
            action: action,
            serverID: serverID,
            serverName: server.name,
            context: context,
            keepAlive: keepAlive,
            rearmCrashLoop: rearmCrashLoop
        )
        runTracked(
            title: title,
            subtitle: context.effectiveCanonicalRoot,
            kind: kind,
            origin: origin,
            resource: identity,
            projectPath: context.effectiveCanonicalRoot,
            arguments: arguments,
            onSuccess: { [weak self] execution in
                guard let self else { return }
                let envelope = try self.validateWorkerRuntimeEnvelope(
                    execution,
                    serverID: serverID,
                    action: action
                )
                guard envelope.ok else {
                    throw RuntimeError(envelope.error ?? envelope.classification)
                }
            }
        )
    }

    func startWorker(_ server: ManagedServer, rearmCrashLoop: Bool = false) {
        runWorkerRuntime(
            "start",
            server: server,
            kind: .startWorker,
            title: rearmCrashLoop ? "Start and re-arm \(server.name)" : "Start \(server.name)",
            keepAlive: server.supervision?.keepAlive,
            rearmCrashLoop: rearmCrashLoop
        )
    }

    func stopWorker(_ server: ManagedServer) {
        runWorkerRuntime(
            "stop",
            server: server,
            kind: .stopWorker,
            title: "Stop \(server.name)"
        )
    }

    func restartWorker(_ server: ManagedServer) {
        runWorkerRuntime(
            "restart",
            server: server,
            kind: .restartWorker,
            title: "Restart \(server.name)",
            keepAlive: server.supervision?.keepAlive
        )
    }

    func setWorkerKeepAlive(_ server: ManagedServer, enabled: Bool) {
        runWorkerRuntime(
            "start",
            server: server,
            kind: .setWorkerKeepAlive,
            title: "Turn Keep alive \(enabled ? "on" : "off") for \(server.name)",
            keepAlive: enabled,
            rearmCrashLoop: false
        )
    }

    func planWorkerRemoval(_ server: ManagedServer) {
        guard server.supervision != nil,
              let origin = server.origin,
              let identity = server.resourceIdentity,
              let context = repositoryExecutionContext(for: server)
        else {
            reportMissingAssociation("Remove \(server.name)")
            return
        }
        let serverID = server.coordinatorID ?? server.id
        guard requireMutationAvailability(
            title: "Plan removal of \(server.name)",
            kind: .workerRemovalPlan,
            origin: origin,
            resource: identity,
            projectPath: context.effectiveCanonicalRoot
        ) else { return }
        let request = beginAction(
            kind: .workerRemovalPlan,
            title: "Plan removal of \(server.name)",
            origin: origin,
            resource: identity,
            projectPath: context.effectiveCanonicalRoot
        )
        Task {
            markActionRunning(request.id)
            let arguments = workerRuntimeArguments(
                action: "remove",
                serverID: serverID,
                serverName: server.name,
                context: context
            )
            do {
                let execution = try await coordinatorService.execute(origin: origin, arguments: arguments)
                let envelope = try validateWorkerRuntimeEnvelope(
                    execution,
                    serverID: serverID,
                    action: "remove"
                )
                guard let plan = envelope.result.plan,
                      ["archive", "purge", "forget"].contains(plan.action),
                      ["worker_remove_plan_ready", "worker_remove_blocked"].contains(envelope.classification)
                else {
                    throw RuntimeError(
                        envelope.error
                            ?? (execution.exitStatus == 0
                                ? "Coordinator returned no exact worker removal plan"
                                : commandFailureMessage(execution))
                    )
                }
                workerRemovalPrompt = WorkerRemovalPrompt(
                    serverID: serverID,
                    serverName: server.name,
                    origin: origin,
                    context: context,
                    plan: plan,
                    archivedInThisJourney: false
                )
                finishAction(request.id, execution: execution)
                clearActionErrorIfPresent(actionID: request.id)
            } catch {
                failAction(request.id, error: error)
                setLastError(
                    title: "Worker removal plan unavailable",
                    summary: error.localizedDescription,
                    details: "No worker lifecycle mutation was applied. Refresh the exact worker and try again.",
                    source: "action",
                    actionID: request.id
                )
            }
        }
    }

    func cancelWorkerRemoval() {
        workerRemovalPrompt = nil
    }

    func applyWorkerRemoval(_ prompt: WorkerRemovalPrompt) {
        let identity = ResourceIdentity(
            origin: prompt.origin,
            kind: .server,
            nativeID: prompt.serverID
        )
        guard requireMutationAvailability(
            title: prompt.plan.isPermanent
                ? "Permanently remove \(prompt.serverName)"
                : "Archive \(prompt.serverName)",
            kind: .workerRemovalApply,
            origin: prompt.origin,
            resource: identity,
            projectPath: prompt.context.effectiveCanonicalRoot
        ) else {
            workerRemovalPrompt = nil
            showActivity()
            return
        }
        let request = beginAction(
            kind: .workerRemovalApply,
            title: prompt.plan.isPermanent
                ? "Permanently remove \(prompt.serverName)"
                : "Archive \(prompt.serverName)",
            origin: prompt.origin,
            resource: identity,
            projectPath: prompt.context.effectiveCanonicalRoot
        )
        workerRemovalPrompt = nil
        showActivity(actionID: request.id)
        Task {
            markActionRunning(request.id)
            do {
                let applyArguments = workerRuntimeArguments(
                    action: "remove",
                    serverID: prompt.serverID,
                    serverName: prompt.serverName,
                    context: prompt.context,
                    removalPlan: prompt.plan
                )
                let execution = try await coordinatorService.execute(
                    origin: prompt.origin,
                    arguments: applyArguments
                )
                guard execution.exitStatus == 0 else {
                    throw RuntimeError(commandFailureMessage(execution))
                }
                let envelope = try validateWorkerRuntimeEnvelope(
                    execution,
                    serverID: prompt.serverID,
                    action: "remove"
                )
                guard envelope.ok else {
                    throw RuntimeError(envelope.error ?? envelope.classification)
                }
                if prompt.plan.isPermanent {
                    guard envelope.classification == "worker_removed" else {
                        throw RuntimeError("Coordinator did not prove permanent worker removal")
                    }
                    workerRemovalPrompt = nil
                    finishAction(request.id, execution: execution)
                    clearActionErrorIfPresent(actionID: request.id)
                    await loadInventory(force: true)
                    return
                }

                guard envelope.classification == "worker_archived" else {
                    throw RuntimeError("Coordinator did not prove the worker archived and stopped")
                }
                // Archive is already a complete mutation. Clear the reviewed
                // archive plan before requesting the distinct, read-only purge
                // plan so a failed follow-up can never re-apply the old plan.
                workerRemovalPrompt = nil
                finishAction(request.id, execution: execution)
                clearActionErrorIfPresent(actionID: request.id)
                await loadInventory(force: true)
                do {
                    let planExecution = try await coordinatorService.execute(
                        origin: prompt.origin,
                        arguments: workerRuntimeArguments(
                            action: "remove",
                            serverID: prompt.serverID,
                            serverName: prompt.serverName,
                            context: prompt.context
                        )
                    )
                    let planned = try validateWorkerRuntimeEnvelope(
                        planExecution,
                        serverID: prompt.serverID,
                        action: "remove"
                    )
                    guard let permanentPlan = planned.result.plan,
                          permanentPlan.isPermanent,
                          ["worker_remove_plan_ready", "worker_remove_blocked"].contains(planned.classification)
                    else {
                        throw RuntimeError(
                            planned.error
                                ?? (planExecution.exitStatus == 0
                                    ? "No permanent-removal plan was returned"
                                    : commandFailureMessage(planExecution))
                        )
                    }
                    workerRemovalPrompt = WorkerRemovalPrompt(
                        serverID: prompt.serverID,
                        serverName: prompt.serverName,
                        origin: prompt.origin,
                        context: prompt.context,
                        plan: permanentPlan,
                        archivedInThisJourney: true
                    )
                } catch {
                    setLastError(
                        title: "Worker archived; permanent-removal plan unavailable",
                        summary: error.localizedDescription,
                        details: "The worker is stopped, fenced, and hidden. Open Archived resources to review permanent removal later.",
                        source: "action",
                        actionID: request.id
                    )
                }
                return
            } catch {
                failAction(request.id, error: error)
                setLastError(
                    title: prompt.plan.isPermanent
                        ? "Permanent worker removal needs attention"
                        : "Worker archive needs attention",
                    summary: error.localizedDescription,
                    details: "The coordinator retains the exact lifecycle fence and plan evidence. No unproved deletion is shown as complete.",
                    source: "action",
                    actionID: request.id
                )
                await loadInventory(force: true)
            }
        }
    }

    func isBackupVerificationInProgress(for container: DockerContainer) -> Bool {
        guard let identity = container.databaseIdentity else { return false }
        return backupVerificationInProgress.contains(identity.id)
    }

    private func rebuildBackupRecords(from backups: [DatabaseBackup]) {
        let activeKeys = Set(backups.map(\.verificationCacheKey))
        verifiedBackupsByKey = verifiedBackupsByKey.filter { activeKeys.contains($0.key) }
        backupRecords = backups.compactMap { backup in
            verifiedBackupsByKey[backup.verificationCacheKey] ?? backup.manifestRecord()
        }
    }

    private func requestBackupVerification(for container: DockerContainer) {
        guard let identity = container.databaseIdentity else { return }
        let candidates: [(backup: DatabaseBackup, record: BackupRecord)] = inventory.backups.compactMap { backup in
            guard let record = backup.manifestRecord(),
                  record.identity.isSameImmutableDatabase(as: identity)
            else { return nil }
            guard backup.normalizedBackupID == nil || record.isStronglyVerified else { return nil }
            return (backup, record)
        }
        guard let candidate = candidates.max(by: { $0.record.createdAt < $1.record.createdAt }) else { return }
        let key = candidate.backup.verificationCacheKey
        if candidate.record.isStronglyVerified {
            verifiedBackupsByKey[key] = candidate.record
            return
        }
        if verifiedBackupsByKey[key] != nil || backupVerificationTasks[key] != nil { return }

        backupVerificationInProgress.insert(identity.id)
        backupVerificationTasks[key] = Task { [weak self] in
            let verified = await Task.detached(priority: .utility) {
                candidate.backup.verifiedRecord()
            }.value
            guard let self else { return }
            self.backupVerificationTasks[key] = nil
            self.backupVerificationInProgress.remove(identity.id)
            guard self.inventory.backups.contains(where: { $0.verificationCacheKey == key }) else { return }
            if let verified {
                self.verifiedBackupsByKey[key] = verified
            }
            self.rebuildBackupRecords(from: self.inventory.backups)
        }
    }

    func restart(_ server: ManagedServer) {
        if server.supervision != nil {
            restartWorker(server)
            return
        }
        guard let origin = server.origin, let identity = server.resourceIdentity, let project = server.project else {
            reportMissingAssociation("Restart \(server.name)")
            return
        }
        runTracked(
            title: "Restart \(server.name)",
            subtitle: project,
            kind: .restartServer,
            origin: origin,
            resource: identity,
            arguments: ["server", "restart", "--agent", agentID, "--project", project, "--name", server.name]
        )
    }

    func stop(_ server: ManagedServer) {
        if server.supervision != nil {
            stopWorker(server)
            return
        }
        guard let origin = server.origin, let identity = server.resourceIdentity, let project = server.project else {
            reportMissingAssociation("Stop \(server.name)")
            return
        }
        runTracked(
            title: "Stop \(server.name)",
            subtitle: project,
            kind: .stopServer,
            origin: origin,
            resource: identity,
            arguments: ["server", "stop", "--agent", agentID, "--project", project, "--name", server.name, "--reason", "Stopped from DevOps Board"]
        )
    }

    func toggle(_ server: ManagedServer) {
        if server.supervision != nil {
            canStopServer(server) ? stopWorker(server) : startWorker(server)
            return
        }
        if canStopServer(server) {
            stop(server)
        } else {
            restart(server)
        }
    }

    func startServer() {
        guard let origin = startDraft.origin ?? defaultActionOrigin else {
            reportAmbiguousSource("Start server")
            return
        }
        let executable = startDraft.executable.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !executable.isEmpty else {
            setLastError(
                title: "Start server failed",
                summary: "Choose an executable before starting the server",
                details: "Server commands are sent as structured arguments; an empty executable cannot be launched.",
                source: "action"
            )
            return
        }
        let argv = [executable] + startDraft.arguments
        guard let encodedArgvData = try? JSONEncoder().encode(argv),
              let encodedArgv = String(data: encodedArgvData, encoding: .utf8)
        else {
            setLastError(
                title: "Start server failed",
                summary: "The structured command could not be encoded",
                details: "Review the executable and argument rows, then try again.",
                source: "action"
            )
            return
        }
        let project = startDraft.project.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? actionProjectPath : startDraft.project
        let cwd = startDraft.cwd.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? project : startDraft.cwd
        var args = [
            "server", "start",
            "--agent", startDraft.agent,
            "--project", project,
            "--name", startDraft.name,
            "--cwd", cwd,
            "--argv", encodedArgv,
        ]
        let preferred = startDraft.preferredPort.trimmingCharacters(in: .whitespacesAndNewlines)
        if let preferredPort = Int(preferred) {
            args.append(contentsOf: ["--range", "\(preferredPort)-\(preferredPort)", "--preferred", "\(preferredPort)"])
        } else {
            args.append(contentsOf: ["--range", startDraft.range])
        }
        if !startDraft.healthURL.isEmpty {
            args.append(contentsOf: ["--health-url", startDraft.healthURL])
        }
        if let leaseID = startDraft.leaseID, !leaseID.isEmpty {
            args.append(contentsOf: ["--lease-id", leaseID])
        }
        guard let identity = startDraftResourceIdentity(origin: origin) else {
            setLastError(
                title: "Start server failed",
                summary: "Choose a server name before starting",
                details: "The action target could not be identified without a non-empty server name.",
                source: "action"
            )
            return
        }
        runTracked(
            title: "Start \(startDraft.name)",
            subtitle: project,
            kind: .startServer,
            origin: origin,
            resource: identity,
            leaseID: startDraft.leaseID,
            projectPath: project,
            arguments: args
        )
        showingStartSheet = false
    }

    func leasePort() {
        guard let origin = leaseOrigin ?? defaultActionOrigin else {
            reportAmbiguousSource("Lease port")
            return
        }
        let args = [
            "port", "lease",
            "--agent", agentID,
            "--project", actionProjectPath,
            "--range", leaseRange,
            "--purpose", "manual"
        ]
        runTracked(
            title: "Lease port",
            subtitle: leaseRange,
            kind: .leasePort,
            origin: origin,
            resource: nil,
            projectPath: actionProjectPath,
            arguments: args,
            refreshAfterSuccess: true
        ) { [weak self] execution in
            guard let self else { return }
            let payload = try JSONDecoder().decode(LeaseCommandPayload.self, from: Data(execution.stdout.utf8))
            let result = LeaseActionResult(origin: origin, payload: payload, actingAgent: agentID)
            self.latestLeaseResult = result
            self.leaseResults[result.identity] = result
        }
        showingLeaseSheet = false
    }

    func prepareLeaseDraft() {
        let available = availableActionOrigins
        if let leaseOrigin,
           let current = available.first(where: { $0.id == leaseOrigin.id })
        {
            self.leaseOrigin = current
            return
        }
        leaseOrigin = defaultActionOrigin
    }

    @discardableResult
    func prepareStartDraft(using lease: LeaseActionResult) -> Bool {
        guard lease.canStartServer else {
            let state = lease.managementStatus
            setLastError(
                title: "Lease cannot start a server",
                summary: "Port \(lease.port) cannot be reused because this lease is \(state)",
                details: "Only an active, unbound manual lease with exact agent and project association can start a server. Lease: \(lease.leaseID)",
                source: "action"
            )
            return false
        }
        guard requireMutationAvailability(
            title: "Use lease",
            kind: .startServer,
            origin: lease.identity.origin,
            resource: nil,
            leaseID: lease.leaseID,
            projectPath: lease.project
        ) else { return false }
        startDraft.origin = lease.identity.origin
        startDraft.leaseID = lease.leaseID
        startDraft.agent = lease.agent ?? agentID
        startDraft.project = lease.project ?? ""
        startDraft.cwd = startDraft.project
        startDraft.preferredPort = String(lease.port)
        startDraft.range = "\(lease.port)-\(lease.port)"
        startDraft.healthURL = "http://127.0.0.1:\(lease.port)/"
        return true
    }

    func releaseLease(_ lease: LeaseActionResult) {
        guard lease.canReleaseDirectly,
              let project = lease.project?.trimmingCharacters(in: .whitespacesAndNewlines),
              !project.isEmpty
        else {
            setLastError(
                title: "Release lease unavailable",
                summary: "Lease \(lease.leaseID) is \(lease.managementStatus)",
                details: "Only an active, unbound lease with exact project association can be released directly. Stop an attached server through its server action.",
                source: "action"
            )
            return
        }
        runTracked(
            title: "Release port \(lease.port)",
            subtitle: lease.leaseID,
            kind: .releasePort,
            origin: lease.identity.origin,
            resource: lease.identity,
            leaseID: lease.leaseID,
            projectPath: project,
            arguments: [
                "port", "release",
                "--lease-id", lease.leaseID,
                "--agent", agentID,
                "--project", project,
            ]
        ) { [weak self] _ in
            guard let self else { return }
            var released = lease
            released.phase = .released
            released.status = "released"
            self.leaseResults[lease.identity] = released
            if self.latestLeaseResult?.identity == lease.identity { self.latestLeaseResult = released }
        }
    }

    private func currentDatabaseForMutation(matching identity: DatabaseIdentity) -> DockerContainer? {
        let matches = inventory.postgres.filter { database in
            guard database.associationError == nil,
                  let currentIdentity = database.databaseIdentity
            else { return false }
            return currentIdentity.isSameImmutableDatabase(as: identity)
        }
        guard matches.count == 1 else { return nil }
        return matches[0]
    }

    func backupDatabase(container: DockerContainer?) {
        guard let container,
              container.associationError == nil,
              let requestedIdentity = container.databaseIdentity
        else {
            setLastError(
                title: "Backup database refused",
                summary: "The selected database does not have authoritative coordinator control",
                details: "Refresh inventory and resolve the repository association or routing identity before backup.",
                source: "action"
            )
            return
        }
        guard let current = currentDatabaseForMutation(matching: requestedIdentity),
              let origin = current.origin,
              let identity = current.databaseIdentity,
              let containerID = identity.containerID,
              let project = current.project,
              !project.isEmpty
        else {
            setLastError(
                title: "Backup database refused",
                summary: "The current inventory no longer identifies one exact database",
                details: "Refresh inventory and retry only after the exact repository association and routing identity are authoritative.",
                source: "action"
            )
            return
        }
        let args = [
            "backup",
            "--container", identity.container,
            "--database", identity.database,
            "--expect-container-id", containerID,
        ]
        runBackupTracked(
            title: "Backup \(identity.database)",
            subtitle: "\(identity.container) · \(origin.label)",
            origin: origin,
            resource: ResourceIdentity(origin: origin, kind: .database, nativeID: "\(containerID)/\(identity.container)/\(identity.database)"),
            container: identity.container,
            containerID: containerID,
            database: identity.database,
            projectRoot: project,
            arguments: args
        )
    }

    func restoreConfirmation(for identity: DatabaseIdentity) -> String {
        "RESTORE \(identity.container)/\(identity.database)"
    }

    func restoreDatabase(target: DatabaseIdentity, backup: BackupRecord, confirmation: String) {
        guard confirmation == restoreConfirmation(for: target) else {
            setLastError(
                title: "Restore confirmation failed",
                summary: "The confirmation value does not match the exact database target",
                details: "Expected: \(restoreConfirmation(for: target))",
                source: "action"
            )
            return
        }
        guard backup.isStronglyVerified else {
            setLastError(
                title: "Restore refused",
                summary: "The selected backup has not passed checksum and restore testing",
                details: backup.compatibilityError ?? "A strongly verified backup is required.",
                source: "action"
            )
            return
        }
        guard backup.identity.isSameImmutableDatabase(as: target) else {
            setLastError(
                title: "Restore refused",
                summary: "The selected backup does not belong to this immutable database target",
                details: "Origin, container name, immutable container id, and database name must all match.",
                source: "action"
            )
            return
        }
        guard let targetContainerID = target.containerID else {
            setLastError(
                title: "Restore refused",
                summary: "The immutable target container id is unavailable",
                details: "Refresh database discovery before restoring.",
                source: "action"
            )
            return
        }
        guard let current = currentDatabaseForMutation(matching: target),
              let projectRoot = current.project,
              !projectRoot.isEmpty
        else {
            setLastError(
                title: "Restore refused",
                summary: "The current inventory does not identify one exact database target",
                details: "Refresh inventory and resolve the repository association or routing identity before restoring.",
                source: "action"
            )
            return
        }
        let resource = ResourceIdentity(
            origin: target.origin,
            kind: .database,
            nativeID: "\(targetContainerID)/\(target.container)/\(target.database)"
        )
        guard requireMutationAvailability(
            title: "Restore \(target.database)",
            kind: .restoreDatabase,
            origin: target.origin,
            resource: resource
        ) else { return }
        let request = beginAction(kind: .restoreDatabase, title: "Restore \(target.database)", resource: resource)
        Task {
            markActionRunning(request.id)
            var retainedExecution: CommandExecution?
            do {
                let authority = try await backupService.executionAuthority(
                    origin: target.origin,
                    projectRoot: projectRoot
                )
                let arguments: [String]
                switch authority {
                case .broker:
                    guard let databaseBackupID = backup.normalizedBackupID,
                          !databaseBackupID.isEmpty,
                          backup.databaseBindingID != nil,
                          backup.dockerResourceID != nil
                    else {
                        throw RuntimeError(
                            "Broker restore requires one strongly verified normalized backup registry identity"
                        )
                    }
                    arguments = [
                        "restore",
                        "--container", target.container,
                        "--database", target.database,
                        "--database-backup-id", databaseBackupID,
                        "--expect-container-id", targetContainerID,
                        "--confirm-restore",
                    ]
                case .direct:
                    let safetyDirectory = URL(fileURLWithPath: backup.path)
                        .deletingLastPathComponent()
                        .appendingPathComponent("pre-restore", isDirectory: true)
                        .path
                    arguments = [
                        "restore",
                        "--container", target.container,
                        "--database", target.database,
                        "--file", backup.path,
                        "--expect-container-id", targetContainerID,
                        "--confirm-restore",
                        "--safety-out-dir", safetyDirectory,
                    ]
                }
                let execution = try await backupService.execute(
                    origin: target.origin,
                    projectRoot: projectRoot,
                    arguments: arguments
                )
                retainedExecution = execution
                if execution.exitStatus == 0 {
                    if authority == .broker {
                        try validateBrokerRestoreResult(
                            execution: execution,
                            target: target,
                            backup: backup
                        )
                    } else {
                        let evidence = try validatedRestoreEvidence(
                            execution: execution,
                            target: target,
                            backup: backup,
                            actionID: request.id
                        )
                        restoreEvidence[target] = evidence
                    }
                    finishAction(request.id, execution: execution)
                    clearActionErrorIfPresent(actionID: request.id)
                    await loadInventory(force: true)
                } else {
                    failAction(request.id, execution: execution, failure: commandFailureMessage(execution))
                    setCommandFailure(
                        title: "Restore \(target.database)",
                        command: ["python3", "<postgres-backup>"] + arguments,
                        result: execution,
                        actionID: request.id
                    )
                }
            } catch {
                failAction(request.id, execution: retainedExecution, failure: error.localizedDescription, error: error)
                setLastError(
                    title: "Restore \(target.database) failed",
                    summary: error.localizedDescription,
                    details: error.localizedDescription,
                    source: "action",
                    actionID: request.id
                )
            }
        }
    }

    private func validateBrokerRestoreResult(
        execution: CommandExecution,
        target: DatabaseIdentity,
        backup: BackupRecord
    ) throws {
        let payload = try JSONDecoder().decode(
            BrokerRestoreCommandPayload.self,
            from: Data(execution.stdout.utf8)
        )
        guard payload.databaseBackupID == backup.normalizedBackupID,
              payload.databaseBindingID == backup.databaseBindingID,
              payload.dockerResourceID == backup.dockerResourceID,
              payload.databaseName == target.database,
              payload.transactional == true,
              payload.status == "restored",
              !(payload.restoreEventID ?? "").isEmpty,
              !(payload.safetyDatabaseBackupID ?? "").isEmpty
        else {
            throw RuntimeError(
                "Broker restore result did not prove the exact normalized database, backup, and transactional safety backup"
            )
        }
    }

    private func validatedRestoreEvidence(
        execution: CommandExecution,
        target: DatabaseIdentity,
        backup: BackupRecord,
        actionID: UUID
    ) throws -> DatabaseRestoreEvidence {
        let payload = try JSONDecoder().decode(RestoreCommandPayload.self, from: Data(execution.stdout.utf8))
        guard payload.container == target.container, payload.database == target.database else {
            throw RuntimeError("Restore result target does not match the requested database")
        }
        guard payload.transactional == true else {
            throw RuntimeError("Restore result did not prove transactional execution")
        }
        guard payload.incomingVerification?.provesStrongVerification == true else {
            throw RuntimeError("Restore result did not prove incoming backup verification")
        }
        guard let safetyBackup = payload.safetyBackup,
              let safetyBackupPath = safetyBackup.backup,
              !safetyBackupPath.isEmpty,
              payload.safetyVerification?.provesStrongVerification == true
        else {
            throw RuntimeError("Restore result did not prove a strongly verified safety backup")
        }
        guard let signature = payload.restoredCatalogSignature else {
            throw RuntimeError("Restore result did not include a restored catalog signature")
        }
        guard let containerID = target.containerID,
              let preflights = payload.containerIdentityPreflights,
              preflights.count >= 3,
              preflights.allSatisfy({ $0.proves(expectedContainerID: containerID) }),
              Set(preflights.compactMap(\.actualID)).count == 1
        else {
            throw RuntimeError("Restore result did not prove immutable container identity through every preflight")
        }
        if let restored = payload.restored {
            let actual = URL(fileURLWithPath: restored).standardizedFileURL.path
            let expected = URL(fileURLWithPath: backup.path).standardizedFileURL.path
            guard actual == expected else { throw RuntimeError("Restore result references a different backup artifact") }
        } else {
            throw RuntimeError("Restore result did not identify the restored backup artifact")
        }
        return DatabaseRestoreEvidence(
            target: target,
            restoredBackupPath: backup.path,
            safetyBackupPath: safetyBackupPath,
            safetyBackupManifest: safetyBackup.manifest,
            safetyBackupSHA256: safetyBackup.sha256,
            incomingVerificationPassed: true,
            safetyVerificationPassed: true,
            transactional: true,
            restoredCatalogSignature: signature,
            containerIdentityPreflights: preflights,
            actionID: actionID,
            completedAt: clock.now()
        )
    }

    func prepareStartDraft() {
        let project = actionProjectPath
        let available = availableActionOrigins
        if let selected = startDraft.origin,
           let current = available.first(where: { $0.id == selected.id })
        {
            startDraft.origin = current
        } else {
            startDraft.origin = defaultActionOrigin
        }
        startDraft.leaseID = nil
        startDraft.agent = agentID
        startDraft.project = project
        startDraft.cwd = project
        startDraft.range = StartServerDraft.defaultRange
        startDraft.preferredPort = ""
        startDraft.healthURL = StartServerDraft.defaultHealthURL
    }

    func dockerLogs(_ container: DockerContainer) {
        guard let name = container.name, let origin = container.origin, let identity = container.resourceIdentity else {
            reportMissingAssociation("Docker logs")
            return
        }
        guard requireMutationAvailability(title: "Docker logs", kind: .dockerLogs, origin: origin, resource: identity) else { return }
        let request = beginAction(kind: .dockerLogs, title: "Docker logs \(name)", resource: identity)
        logEvidence[identity] = RetainedLogEvidence(
            resource: identity,
            actionID: request.id,
            source: origin,
            requestedAt: clock.now(),
            completedAt: nil,
            state: .loading,
            displayText: "",
            stdout: "",
            stderr: "",
            exitStatus: nil,
            outputTruncated: false
        )
        Task {
            markActionRunning(request.id)
            var retainedExecution: CommandExecution?
            do {
                let execution = try await coordinatorService.execute(
                    origin: origin,
                    arguments: ["docker", "logs", "--container", name, "--tail", "80"]
                )
                retainedExecution = execution
                guard execution.exitStatus == 0 else { throw RuntimeError(commandFailureMessage(execution)) }
                let payload = try? JSONDecoder().decode(DockerCommandPayload.self, from: Data(execution.stdout.utf8))
                let text = payload?.stdout ?? execution.stdout
                dockerLogResults[identity] = text
                logEvidence[identity] = retainedLogEvidence(
                    request: request,
                    origin: origin,
                    execution: execution,
                    displayText: text,
                    failure: nil
                )
                serverLogTitle = "\(name) Docker logs"
                serverLogMetadata = "Source: \(origin.label) · Exit: \(payload?.returncode ?? execution.exitStatus)"
                serverLogText = text.isEmpty ? "No log output recorded." : text
                showingServerLogs = true
                finishAction(request.id, execution: execution)
            } catch {
                failAction(request.id, execution: retainedExecution, failure: error.localizedDescription, error: error)
                logEvidence[identity] = retainedLogEvidence(
                    request: request,
                    origin: origin,
                    execution: retainedExecution,
                    displayText: retainedExecution.flatMap { $0.stderr.isEmpty ? nil : $0.stderr } ?? error.localizedDescription,
                    failure: error
                )
                setLastError(
                    title: "Docker logs failed",
                    summary: error.localizedDescription,
                    details: commandFailureDetails(
                        title: "Docker logs",
                        command: ["python3", "<coordinator>", "docker", "logs", "--container", name, "--tail", "80"],
                        result: retainedExecution,
                        thrownError: error
                    ),
                    source: "action",
                    actionID: request.id
                )
            }
        }
    }

    func restartDocker(_ container: DockerContainer) {
        guard let name = container.name, let origin = container.origin, let identity = container.resourceIdentity, let project = container.project else {
            reportMissingAssociation("Restart container")
            return
        }
        runTracked(title: "Restart container", subtitle: name, kind: .restartDocker, origin: origin, resource: identity, arguments: ["docker", "restart", "--agent", agentID, "--project", project, "--container", name])
    }

    func toggleDocker(_ container: DockerContainer) {
        if container.isRunning {
            stopDocker(container)
        } else {
            startDocker(container)
        }
    }

    func startDocker(_ container: DockerContainer) {
        guard let name = container.name, let origin = container.origin, let identity = container.resourceIdentity, let project = container.project else {
            reportMissingAssociation("Start container")
            return
        }
        runTracked(title: "Start container", subtitle: name, kind: .startDocker, origin: origin, resource: identity, arguments: ["docker", "start", "--agent", agentID, "--project", project, "--container", name])
    }

    func stopDocker(_ container: DockerContainer) {
        guard let name = container.name, let origin = container.origin, let identity = container.resourceIdentity, let project = container.project else {
            reportMissingAssociation("Stop container")
            return
        }
        runTracked(title: "Stop container", subtitle: name, kind: .stopDocker, origin: origin, resource: identity, arguments: ["docker", "stop", "--agent", agentID, "--project", project, "--container", name])
    }

    func showServerLogs(_ server: ManagedServer) {
        guard let origin = server.origin, let identity = server.resourceIdentity, let project = server.project else {
            reportMissingAssociation("Server logs")
            return
        }
        guard requireMutationAvailability(title: "Server logs", kind: .serverLogs, origin: origin, resource: identity) else { return }
        serverLogTitle = "\(server.name) logs"
        serverLogMetadata = "Loading logs..."
        serverLogText = ""
        showingServerLogs = true
        let request = beginAction(kind: .serverLogs, title: "Logs \(server.name)", resource: identity)
        Task {
            logEvidence[identity] = RetainedLogEvidence(
                resource: identity,
                actionID: request.id,
                source: origin,
                requestedAt: clock.now(),
                completedAt: nil,
                state: .loading,
                displayText: "",
                stdout: "",
                stderr: "",
                exitStatus: nil,
                outputTruncated: false
            )
            var retainedExecution: CommandExecution?
            do {
                markActionRunning(request.id)
                let result = try await coordinatorService.execute(
                    origin: origin,
                    arguments: ["server", "logs", "--server-id", server.coordinatorID ?? server.id, "--project", project, "--name", server.name, "--tail", "300"]
                )
                retainedExecution = result
                guard result.exitStatus == 0 else {
                    failAction(request.id, execution: result, failure: commandFailureMessage(result))
                    throw RuntimeError(commandFailureMessage(result))
                }
                let payload = try JSONDecoder().decode(ServerLogPayload.self, from: Data(result.stdout.utf8))
                let reason = payload.server.stoppedReason ?? server.stoppedReason ?? "No stop reason recorded"
                let stoppedAt = payload.server.stoppedAt ?? server.stoppedAt ?? "Not stopped"
                let logPath = payload.server.logPath ?? server.logPath ?? "No log path"
                serverLogTitle = "\(payload.server.name ?? server.name) logs"
                serverLogMetadata = "Status: \(payload.server.status ?? server.status ?? "unknown") | Stopped: \(stoppedAt) | Reason: \(reason) | Log: \(logPath)"
                serverLogText = payload.text.isEmpty ? "No log output recorded yet." : payload.text
                logEvidence[identity] = retainedLogEvidence(
                    request: request,
                    origin: origin,
                    execution: result,
                    displayText: payload.text,
                    failure: nil
                )
                finishAction(request.id, execution: result)
            } catch {
                serverLogMetadata = "Failed to load logs"
                serverLogText = error.localizedDescription
                if actionResults[request.id]?.phase == .running {
                    failAction(request.id, execution: retainedExecution, failure: error.localizedDescription, error: error)
                }
                logEvidence[identity] = retainedLogEvidence(
                    request: request,
                    origin: origin,
                    execution: retainedExecution,
                    displayText: retainedExecution.flatMap { $0.stderr.isEmpty ? nil : $0.stderr } ?? error.localizedDescription,
                    failure: error
                )
            }
        }
    }

    private func retainedLogEvidence(
        request: ActionRequest,
        origin: CoordinatorOrigin,
        execution: CommandExecution?,
        displayText: String,
        failure: Error?
    ) -> RetainedLogEvidence {
        let state: LogEvidenceState
        if execution?.timedOut == true {
            state = .timedOut
        } else if execution?.cancelled == true || failure is CancellationError {
            state = .cancelled
        } else if execution == nil, failure != nil {
            state = .unavailable
        } else if failure != nil || execution?.exitStatus != 0 {
            state = .failed
        } else if displayText.isEmpty {
            state = .empty
        } else {
            state = .available
        }
        return RetainedLogEvidence(
            resource: request.resource!,
            actionID: request.id,
            source: origin,
            requestedAt: actionResults[request.id]?.queuedAt ?? clock.now(),
            completedAt: clock.now(),
            state: state,
            displayText: displayText,
            stdout: execution?.stdout ?? "",
            stderr: execution?.stderr ?? "",
            exitStatus: execution?.exitStatus,
            outputTruncated: execution?.outputTruncated ?? false
        )
    }

    var hasStoppableResources: Bool {
        inventory.servers.contains { server in
            guard canStopServer(server),
                  let identity = server.resourceIdentity,
                  let project = server.project?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !project.isEmpty
            else { return false }
            return mutationAvailability(
                kind: .stopServer,
                origin: identity.origin,
                resource: identity
            ).isAllowed
        } || inventory.docker.containers.contains { container in
            guard container.isRunning,
                  let identity = container.resourceIdentity,
                  let name = container.name?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !name.isEmpty,
                  let project = container.project?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !project.isEmpty
            else { return false }
            return mutationAvailability(
                kind: .stopDocker,
                origin: identity.origin,
                resource: identity
            ).isAllowed
        }
    }

    func setBulkSelected(_ identity: ResourceIdentity, selected: Bool) {
        let identity = identity.kind == .database
            ? ResourceIdentity(origin: identity.origin, kind: .docker, nativeID: identity.nativeID)
            : identity
        if selected {
            bulkSelection.select(identity)
        } else {
            bulkSelection.deselect(identity)
        }
        pendingBulkStopPlan = nil
    }

    func clearBulkSelection() {
        bulkSelection.clear()
        pendingBulkStopPlan = nil
    }

    @discardableResult
    func prepareBulkStop() -> BulkStopPlan? {
        let identities = bulkSelection.selected
        guard !identities.isEmpty else {
            setLastError(
                title: "Select resources to stop",
                summary: "No resources are selected",
                details: "Bulk stop requires explicit resource selection; opening or activating an item never selects it for destruction.",
                source: "action"
            )
            pendingBulkStopPlan = nil
            return nil
        }
        guard identities.count <= Self.bulkStopMaximumItems else {
            setLastError(
                title: "Bulk stop selection is too large",
                summary: "Select at most \(Self.bulkStopMaximumItems) resources",
                details: "The bounded bulk executor refuses \(identities.count) resources.",
                source: "action"
            )
            pendingBulkStopPlan = nil
            return nil
        }
        do {
            let items = try bulkStopPlanItems(for: identities)
            let plan = BulkStopPlan(preparedAt: clock.now(), items: items)
            pendingBulkStopPlan = plan
            return plan
        } catch {
            setLastError(
                title: "Bulk stop cannot be prepared",
                summary: error.localizedDescription,
                details: error.localizedDescription,
                source: "action"
            )
            pendingBulkStopPlan = nil
            return nil
        }
    }

    @discardableResult
    func executeBulkStop(planID: UUID, confirmation: String) -> Bool {
        guard let plan = pendingBulkStopPlan, plan.id == planID else {
            setLastError(
                title: "Bulk stop refused",
                summary: "The prepared selection is missing or has changed",
                details: "Prepare the current selection again before confirming.",
                source: "action"
            )
            return false
        }
        guard confirmation == plan.confirmationText else {
            setLastError(
                title: "Bulk stop confirmation failed",
                summary: "The confirmation does not match this exact selection",
                details: "Expected: \(plan.confirmationText)",
                source: "action"
            )
            return false
        }
        do {
            let currentItems = try bulkStopPlanItems(for: plan.items.map(\.identity))
            guard bulkStopFingerprint(items: currentItems) == plan.fingerprint else {
                throw RuntimeError("Resource or source state changed after confirmation was prepared")
            }
        } catch {
            setLastError(
                title: "Bulk stop refused",
                summary: error.localizedDescription,
                details: "Refresh and prepare the selection again.",
                source: "action"
            )
            return false
        }
        pendingBulkStopPlan = nil
        Task { await executeBulkStopPlan(plan) }
        return true
    }

    private func executeBulkStopPlan(_ plan: BulkStopPlan) async {
        var results: [ResourceIdentity: RetainedActionResult] = [:]
        for expected in plan.items {
            let identity = expected.identity
            let kind: ActionKind = identity.kind == .server ? .stopServer : .stopDocker
            let revalidation: Result<BulkStopPlanItem, Error>
            do {
                guard let current = try bulkStopPlanItems(for: [identity]).first else {
                    throw RuntimeError("Selected resource is no longer present")
                }
                revalidation = .success(current)
            } catch {
                revalidation = .failure(error)
            }
            let request = beginAction(kind: kind, title: "Stop \(expected.displayName)", resource: identity)
            markActionRunning(request.id)
            var retainedExecution: CommandExecution?
            do {
                let current = try revalidation.get()
                guard current == expected else { throw RuntimeError("Selected resource changed before it could be stopped") }
                let execution: CommandExecution
                switch identity.kind {
                case .server:
                    guard let server = inventory.servers.first(where: { $0.resourceIdentity == identity }) else {
                        throw RuntimeError("Selected server is no longer present")
                    }
                    execution = try await coordinatorService.execute(
                        origin: identity.origin,
                        arguments: ["server", "stop", "--agent", agentID, "--project", current.project, "--name", server.name, "--reason", "Stopped from confirmed bulk selection"]
                    )
                case .docker:
                    guard let container = (inventory.docker.containers + inventory.postgres).first(where: {
                        $0.origin?.id == identity.origin.id && ($0.id ?? $0.name) == identity.nativeID
                    }), let name = container.name else {
                        throw RuntimeError("Selected container is no longer present")
                    }
                    execution = try await coordinatorService.execute(
                        origin: identity.origin,
                        arguments: ["docker", "stop", "--agent", agentID, "--project", current.project, "--container", name]
                    )
                default:
                    throw RuntimeError("Resource type \(identity.kind.rawValue) cannot be bulk-stopped")
                }
                retainedExecution = execution
                if execution.exitStatus == 0 {
                    finishAction(request.id, execution: execution)
                } else {
                    failAction(request.id, execution: execution, failure: commandFailureMessage(execution))
                }
            } catch {
                failAction(request.id, execution: retainedExecution, failure: error.localizedDescription, error: error)
            }
            if let result = actionResults[request.id] { results[identity] = result }
        }
        latestBulkActionResult = BulkActionResult(selection: plan.selection, results: results)
        bulkSelection.clear()
        await loadInventory(force: true)
    }

    private func bulkStopPlanItems(for identities: [ResourceIdentity]) throws -> [BulkStopPlanItem] {
        try identities.sorted().map { identity in
            guard identity.kind == .server || identity.kind == .docker else {
                throw RuntimeError("Resource type \(identity.kind.rawValue) cannot be bulk-stopped")
            }
            let kind: ActionKind = identity.kind == .server ? .stopServer : .stopDocker
            let availability = mutationAvailability(kind: kind, origin: identity.origin, resource: identity)
            guard availability.isAllowed else { throw RuntimeError(availability.message ?? "Resource is unavailable") }
            guard !actionResults.values.contains(where: {
                ($0.phase == .queued || $0.phase == .running) && $0.request.resource == identity
            }) else { throw RuntimeError("Another action is already running for \(identity.nativeID)") }
            guard let source = sourceStates.first(where: { $0.origin.id == identity.origin.id }), source.phase == .loaded else {
                throw RuntimeError("Coordinator source \(identity.origin.label) is not freshly loaded")
            }
            if identity.kind == .server {
                guard let server = inventory.servers.first(where: { $0.resourceIdentity == identity }),
                      canStopServer(server),
                      let project = server.project,
                      !project.isEmpty
                else { throw RuntimeError("Selected server is stale, stopped, or lacks a canonical project") }
                return BulkStopPlanItem(
                    identity: identity,
                    expectedStatus: (server.status ?? "unknown").lowercased(),
                    project: project,
                    displayName: server.name,
                    sourceCheckedAt: source.checkedAt
                )
            }
            guard let container = (inventory.docker.containers + inventory.postgres).first(where: {
                $0.origin?.id == identity.origin.id && ($0.id ?? $0.name) == identity.nativeID
            }), container.isRunning, let project = container.project, !project.isEmpty else {
                throw RuntimeError("Selected container is stale, stopped, or lacks a canonical project")
            }
            return BulkStopPlanItem(
                identity: identity,
                expectedStatus: (container.status ?? "unknown").lowercased(),
                project: project,
                displayName: container.name ?? identity.nativeID,
                sourceCheckedAt: source.checkedAt
            )
        }
    }

    private func filterDocker(_ containers: [DockerContainer]) -> [DockerContainer] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return containers.filter { container in
            let matchesFilter: Bool
            switch filter {
            case .all:
                matchesFilter = true
            case .running:
                matchesFilter = isRunningStatus(container.status)
            case .unhealthy:
                matchesFilter = dockerRequiresAttention(container)
                    && hasLoadedEvidence(
                        primary: container.origin,
                        observations: container.observationOrigins
                    )
            case .stopped:
                matchesFilter = isStoppedStatus(container.status)
            }
            guard matchesFilter else { return false }
            guard !query.isEmpty else { return true }
            return [container.name, container.image, container.status, container.ports]
                .compactMap { $0?.lowercased() }
                .contains { $0.contains(query) }
        }
    }

    private func hasBackup(for container: DockerContainer) -> Bool {
        verifiedBackup(for: container) != nil
    }

    func verifiedBackup(for container: DockerContainer) -> BackupRecord? {
        guard let identity = container.databaseIdentity else { return nil }
        return newestVerifiedBackup(for: identity, in: backupRecords)
    }

    private func keepSelectionValid() {
        if let selectedServerID, !presentedServerRows.contains(where: { $0.id == selectedServerID }) {
            self.selectedServerID = nil
        }
        if let selectedDockerID,
           !inventory.docker.containers.contains(where: { $0.containerSelectionID == selectedDockerID })
        {
            self.selectedDockerID = nil
        }
        if let selectedDatabaseID,
           !inventory.postgres.contains(where: { $0.databaseSelectionID == selectedDatabaseID })
        {
            self.selectedDatabaseID = nil
        }
        if selectedServerID == nil, selectedDockerID == nil, selectedDatabaseID == nil {
            if let fallback = presentedServerRows.first {
                selectedServerID = fallback.id
                sidebarSelection = .server(fallback.id)
                activeTab = .servers
            }
        }
    }

    private func runTracked(
        title: String,
        subtitle: String,
        kind: ActionKind,
        origin: CoordinatorOrigin,
        resource: ResourceIdentity?,
        leaseID: String? = nil,
        projectPath: String? = nil,
        arguments: [String],
        refreshAfterSuccess: Bool = true,
        onSuccess: (@MainActor (CommandExecution) throws -> Void)? = nil
    ) {
        guard requireMutationAvailability(
            title: title,
            kind: kind,
            origin: origin,
            resource: resource,
            leaseID: leaseID,
            projectPath: projectPath
        ) else { return }
        let request = beginAction(
            kind: kind,
            title: title,
            origin: origin,
            resource: resource,
            leaseID: leaseID,
            projectPath: projectPath
        )
        Task {
            markActionRunning(request.id)
            do {
                let result = try await coordinatorService.execute(origin: origin, arguments: arguments)
                if result.exitStatus == 0 {
                    do {
                        try onSuccess?(result)
                    } catch {
                        failAction(request.id, execution: result, failure: "Could not decode action result: \(error.localizedDescription)")
                        setLastError(
                            title: "\(title) result was invalid",
                            summary: error.localizedDescription,
                            details: "stdout:\n\(result.stdout)\n\nstderr:\n\(result.stderr)",
                            source: "action",
                            actionID: request.id
                        )
                        return
                    }
                    finishAction(request.id, execution: result)
                    clearActionErrorIfPresent(actionID: request.id)
                    if refreshAfterSuccess { await loadInventory(force: true) }
                } else {
                    failAction(request.id, execution: result, failure: commandFailureMessage(result))
                    setCommandFailure(
                        title: title,
                        command: ["python3", "<coordinator>"] + arguments,
                        result: result,
                        actionID: request.id
                    )
                }
            } catch {
                failAction(request.id, error: error)
                setLastError(
                    title: "\(title) failed",
                    summary: error.localizedDescription,
                    details: commandFailureDetails(
                        title: title,
                        command: ["python3", "<coordinator>"] + arguments,
                        result: nil,
                        thrownError: error
                    ),
                    source: "action",
                    actionID: request.id
                )
            }
        }
    }

    private func runBackupTracked(
        title: String,
        subtitle: String,
        origin: CoordinatorOrigin,
        resource: ResourceIdentity,
        container: String,
        containerID: String,
        database: String,
        projectRoot: String,
        arguments: [String]
    ) {
        guard requireMutationAvailability(title: title, kind: .backupDatabase, origin: origin, resource: resource) else { return }
        let request = beginAction(kind: .backupDatabase, title: title, origin: origin, resource: resource)
        Task {
            markActionRunning(request.id)
            var retainedExecution: CommandExecution?
            do {
                let authority = try await backupService.executionAuthority(
                    origin: origin,
                    projectRoot: projectRoot
                )
                let backup = try await backupService.execute(
                    origin: origin,
                    projectRoot: projectRoot,
                    arguments: arguments
                )
                retainedExecution = backup
                guard backup.exitStatus == 0 else {
                    failAction(request.id, execution: backup, failure: commandFailureMessage(backup))
                    setCommandFailure(
                        title: title,
                        command: ["python3", "<postgres-backup>"] + arguments,
                        result: backup,
                        actionID: request.id
                    )
                    return
                }
                if authority == .broker {
                    let payload = try JSONDecoder().decode(
                        BrokerBackupCommandPayload.self,
                        from: Data(backup.stdout.utf8)
                    )
                    guard !(payload.databaseBackupID ?? "").isEmpty,
                          !(payload.databaseBindingID ?? "").isEmpty,
                          !(payload.dockerResourceID ?? "").isEmpty,
                          payload.databaseName == database,
                          payload.verificationStatus == "strong",
                          payload.status == "available"
                    else {
                        throw RuntimeError(
                            "Broker backup result did not prove one strongly verified normalized backup for the exact database"
                        )
                    }
                    finishAction(request.id, execution: backup)
                    clearActionErrorIfPresent(actionID: request.id)
                    await loadInventory(force: true)
                    return
                }
                let payload = try JSONDecoder().decode(BackupCommandPayload.self, from: Data(backup.stdout.utf8))
                let verifyArguments = [
                    "verify",
                    "--container", container,
                    "--database", database,
                    "--file", payload.backup,
                    "--expect-container-id", containerID,
                    "--test-restore",
                ]
                let verification = try await backupService.execute(
                    origin: origin,
                    projectRoot: projectRoot,
                    arguments: verifyArguments
                )
                let combined = CommandExecution(
                    stdout: backup.stdout + "\n" + verification.stdout,
                    stderr: [backup.stderr, verification.stderr].filter { !$0.isEmpty }.joined(separator: "\n"),
                    exitStatus: verification.exitStatus,
                    timedOut: backup.timedOut || verification.timedOut,
                    cancelled: backup.cancelled || verification.cancelled,
                    outputTruncated: backup.outputTruncated || verification.outputTruncated
                )
                retainedExecution = combined
                if verification.exitStatus == 0 {
                    finishAction(request.id, execution: combined)
                    clearActionErrorIfPresent(actionID: request.id)
                    await loadInventory(force: true)
                } else {
                    failAction(request.id, execution: combined, failure: commandFailureMessage(verification))
                    setCommandFailure(
                        title: "Verify \(database)",
                        command: ["python3", "<postgres-backup>"] + verifyArguments,
                        result: verification,
                        actionID: request.id
                    )
                }
            } catch {
                failAction(request.id, execution: retainedExecution, failure: error.localizedDescription, error: error)
                setLastError(
                    title: "\(title) failed",
                    summary: error.localizedDescription,
                    details: commandFailureDetails(
                        title: title,
                        command: ["python3", "<postgres-backup>"] + arguments,
                        result: nil,
                        thrownError: error
                    ),
                    source: "action",
                    actionID: request.id
                )
            }
        }
    }

    @discardableResult
    private func beginAction(
        kind: ActionKind,
        title: String,
        origin: CoordinatorOrigin? = nil,
        resource: ResourceIdentity?,
        leaseID: String? = nil,
        projectPath: String? = nil
    ) -> ActionRequest {
        let request = ActionRequest(
            kind: kind,
            title: title,
            origin: origin,
            resource: resource,
            leaseID: leaseID,
            projectPath: projectPath ?? projectPathForConflict(resource: resource)
        )
        actionResults[request.id] = RetainedActionResult(request: request, phase: .queued, queuedAt: clock.now())
        let completed = actionResults.values
            .filter { $0.phase != .queued && $0.phase != .running }
            .sorted { $0.queuedAt < $1.queuedAt }
        for stale in completed.prefix(max(0, actionResults.count - 200)) {
            actionResults.removeValue(forKey: stale.id)
            retirementRecoveryContexts.removeValue(forKey: stale.id)
            if selectedActionResultID == stale.id {
                selectedActionResultID = nil
            }
        }
        return request
    }

    private func markActionRunning(_ id: UUID) {
        actionResults[id]?.phase = .running
        actionResults[id]?.startedAt = clock.now()
    }

    private func finishAction(_ id: UUID, execution: CommandExecution) {
        actionResults[id]?.phase = .succeeded
        actionResults[id]?.finishedAt = clock.now()
        actionResults[id]?.exitStatus = execution.exitStatus
        actionResults[id]?.stdout = execution.stdout
        actionResults[id]?.stderr = execution.stderr
        actionResults[id]?.coordinatorOperationID = operationID(from: execution.stdout)
        actionResults[id]?.outputTruncated = execution.outputTruncated
    }

    private func failAction(_ id: UUID, execution: CommandExecution? = nil, failure: String? = nil, error: Error? = nil) {
        if execution?.timedOut == true {
            actionResults[id]?.phase = .timedOut
        } else if execution?.cancelled == true || error is CancellationError {
            actionResults[id]?.phase = .cancelled
        } else {
            actionResults[id]?.phase = .failed
        }
        actionResults[id]?.finishedAt = clock.now()
        actionResults[id]?.exitStatus = execution?.exitStatus
        actionResults[id]?.stdout = execution?.stdout ?? ""
        actionResults[id]?.stderr = execution?.stderr ?? ""
        actionResults[id]?.failure = failure ?? error?.localizedDescription ?? "Action failed"
        actionResults[id]?.coordinatorOperationID = execution.flatMap { operationID(from: $0.stdout) }
        actionResults[id]?.outputTruncated = execution?.outputTruncated ?? false
    }

    private func operationID(from output: String) -> String? {
        guard let data = output.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        if let value = object["operation_id"] as? String { return value }
        if let operation = object["operation"] as? [String: Any], let value = operation["id"] as? String { return value }
        return nil
    }

    private func runProjectRuntime(_ action: String, group: ProjectGroup) {
        guard let projectPath = group.projectPath else {
            setLastError(
                title: "Project runtime unavailable",
                summary: "No canonical project path is known for \(group.name)",
                details: "Refresh the coordinator inventory before acting on this project.",
                source: "action"
            )
            return
        }
        let kind: ActionKind = switch action {
        case "start": .projectStart
        case "restart": .projectRestart
        case "stop": .projectStop
        default: .projectStatus
        }
        let availability = projectMutationAvailability(kind: kind, group: group)
        guard availability.isAllowed else {
            let message = availability.message ?? "The project runtime action is unavailable"
            setLastError(
                title: "Project runtime \(action) unavailable",
                summary: message,
                details: message,
                source: "action"
            )
            return
        }
        guard let origin = group.actionOrigin else {
            reportAmbiguousSource("Project runtime \(action)")
            return
        }
        let identity = ResourceIdentity(origin: origin, kind: .project, nativeID: projectPath)
        let request = beginAction(kind: kind, title: "Project \(action) \(group.name)", resource: identity)
        Task {
            markActionRunning(request.id)
            var args = ["project", action, "--project", projectPath]
            if action == "start" || action == "restart" || action == "stop" {
                args.append(contentsOf: ["--agent", agentID])
            }
            var retainedExecution: CommandExecution?
            do {
                let result = try await coordinatorService.execute(origin: origin, arguments: args)
                retainedExecution = result
                let report = decodeProjectRuntimeReport(from: result)
                if let report { projectRuntimeReports[group.id] = report }

                if result.exitStatus != 0 {
                    failAction(request.id, execution: result, failure: commandFailureMessage(result))
                    setLastError(
                        title: "Project runtime \(action) failed",
                        summary: projectRuntimeFailureSummary(
                            group: group,
                            reason: commandFailureMessage(result),
                            report: report
                        ),
                        details: projectCommandFailureDetails(
                            action: action,
                            group: group,
                            command: ["python3", "<coordinator>"] + args,
                            result: result,
                            report: report
                        ),
                        source: "action",
                        actionID: request.id
                    )
                } else {
                    guard let report else {
                        throw RuntimeError("Coordinator returned no project runtime report")
                    }
                    let mutating = action == "start" || action == "restart" || action == "stop"
                    if !mutating || report.ok == true {
                        finishAction(request.id, execution: result)
                    } else {
                        let reason = report.classification ?? report.classifications?.joined(separator: ", ") ?? "runtime objective not complete"
                        failAction(request.id, execution: result, failure: reason)
                    }
                    if report.ok == true || !mutating {
                        clearActionErrorIfPresent(actionID: request.id)
                    } else {
                        let reason = report.classification ?? report.classifications?.joined(separator: ", ") ?? "runtime not ready"
                        setLastError(
                            title: "Project runtime \(action) failed",
                            summary: projectRuntimeFailureSummary(group: group, reason: reason, report: report),
                            details: projectRuntimeFailureDetails(action: action, group: group, report: report),
                            source: "action",
                            actionID: request.id
                        )
                    }
                }
            } catch {
                failAction(
                    request.id,
                    execution: retainedExecution,
                    failure: error.localizedDescription,
                    error: error
                )
                setLastError(
                    title: "Project runtime \(action) failed",
                    summary: "\(group.name): \(error.localizedDescription)",
                    details: commandFailureDetails(
                        title: "Project runtime \(action) for \(group.name)",
                        command: ["python3", "<coordinator>"] + args,
                        result: retainedExecution,
                        thrownError: error
                    ),
                    source: "action",
                    actionID: request.id
                )
            }
            await loadInventory(force: true)
        }
    }

    private func ensureSuccess(_ result: CommandExecution) throws {
        guard result.exitStatus == 0 else {
            throw RuntimeError(result.stderr.isEmpty ? result.stdout : result.stderr)
        }
    }

    private func setCommandFailure(
        title: String,
        command: [String],
        result: CommandExecution,
        actionID: UUID
    ) {
        let message = commandFailureMessage(result)
        setLastError(
            title: "\(title) failed",
            summary: message,
            details: commandFailureDetails(title: title, command: command, result: result, thrownError: nil),
            source: "action",
            actionID: actionID
        )
    }

    private func setLastError(
        title: String,
        summary: String,
        details: String,
        source: String,
        actionID: UUID? = nil
    ) {
        let cleanSummary = summary.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanDetails = details.trimmingCharacters(in: .whitespacesAndNewlines)
        lastErrorTitle = title
        lastError = cleanSummary
        lastErrorDetails = cleanDetails
        lastErrorSource = source
        let issue = OpsIssue(
            kind: source == "action" ? .action : (source == "configuration" ? .configuration : .inventory),
            title: title,
            summary: cleanSummary,
            details: cleanDetails,
            createdAt: clock.now(),
            relatedActionID: source == "action" ? actionID : nil
        )
        if source == "action" {
            replaceActionIssue(with: issue)
        } else {
            inventoryIssue = issue
        }
    }

    private func commandFailureMessage(_ result: CommandExecution) -> String {
        if result.timedOut { return "Command timed out" }
        if result.cancelled { return "Command was cancelled" }
        let raw = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? result.stdout : result.stderr
        if let data = raw.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String,
           !error.isEmpty {
            return error
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "Exited with status \(result.exitStatus)" : trimmed
    }

    private func commandFailureDetails(
        title: String,
        command: [String],
        result: CommandExecution?,
        thrownError: Error?
    ) -> String {
        var lines = [
            title,
            "Command: \(shellCommand(command))"
        ]
        if let result {
            lines.append("Exit status: \(result.exitStatus)")
            if !result.stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                lines.append("stderr:\n\(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
            if !result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                lines.append("stdout:\n\(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        }
        if let thrownError {
            lines.append("Error: \(thrownError.localizedDescription)")
        }
        return lines.joined(separator: "\n\n")
    }

    private func decodeProjectRuntimeReport(from result: CommandExecution) -> ProjectRuntimeReport? {
        for text in [result.stdout, result.stderr] {
            guard let data = text.data(using: .utf8), !data.isEmpty else { continue }
            if let direct = try? JSONDecoder().decode(ProjectRuntimeReport.self, from: data) {
                return direct
            }
            guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                continue
            }
            for key in ["report", "result", "partial_result"] {
                guard let nested = object[key],
                      JSONSerialization.isValidJSONObject(nested),
                      let nestedData = try? JSONSerialization.data(withJSONObject: nested),
                      let report = try? JSONDecoder().decode(ProjectRuntimeReport.self, from: nestedData)
                else { continue }
                return report
            }
        }
        return nil
    }

    private func projectCommandFailureDetails(
        action: String,
        group: ProjectGroup,
        command: [String],
        result: CommandExecution,
        report: ProjectRuntimeReport?
    ) -> String {
        var sections: [String] = []
        if let report {
            sections.append(projectRuntimeFailureDetails(action: action, group: group, report: report))
        }
        sections.append(
            commandFailureDetails(
                title: "Project runtime \(action) for \(group.name)",
                command: command,
                result: result,
                thrownError: nil
            )
        )
        return sections.joined(separator: "\n\n")
    }

    private func projectRuntimeFailureSummary(
        group: ProjectGroup,
        reason: String,
        report: ProjectRuntimeReport?
    ) -> String {
        if report?.partial == true {
            return "\(group.name): \(reason) · partial changes applied"
        }
        if report?.partial == false {
            return "\(group.name): \(reason) · preflight stopped before changes"
        }
        return "\(group.name): \(reason)"
    }

    private func projectRuntimeFailureDetails(action: String, group: ProjectGroup, report: ProjectRuntimeReport) -> String {
        var lines = [
            "Project runtime \(action) for \(group.name)",
            "Project: \(report.project ?? group.projectPath ?? "unknown")",
            "Classification: \(report.classification ?? report.classifications?.joined(separator: ", ") ?? "not ready")"
        ]
        if report.partial == true {
            lines.append("Outcome: Partial changes were applied before the failure; refreshed inventory is authoritative.")
        } else if report.partial == false, report.ok == false {
            lines.append("Outcome: No runtime changes were applied before the preflight failure.")
        }
        let failedServices = report.services.filter { $0.ok == false || $0.classification != nil }
        if !failedServices.isEmpty {
            lines.append("Failed services:")
            for service in failedServices {
                lines.append("- \(service.name ?? service.container ?? service.type ?? "service"): \(service.classification ?? service.status ?? "failed")")
                if let reason = service.previousExitReason, !reason.isEmpty {
                    lines.append("  previous exit: \(reason)")
                }
                if let logs = service.recentLogs, !logs.isEmpty {
                    lines.append("  recent logs:\n\(logs)")
                }
            }
        }
        if let errors = report.actionErrors, !errors.isEmpty {
            lines.append("Action errors:")
            for error in errors {
                lines.append("- \(error.name ?? "action"): \(error.error ?? error.classification ?? "failed")")
            }
        }
        return lines.joined(separator: "\n")
    }
}

func shellCommand(_ parts: [String]) -> String {
    parts.map(shellQuote).joined(separator: " ")
}

func shellQuote(_ value: String) -> String {
    if value.range(of: #"^[A-Za-z0-9_@%+=:,./-]+$"#, options: .regularExpression) != nil {
        return value
    }
    return "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
}

struct StartServerArgument: Identifiable, Hashable {
    let id: UUID
    var value: String

    init(id: UUID = UUID(), value: String) {
        self.id = id
        self.value = value
    }
}

struct StartServerDraft {
    static let defaultRange = "3000-3999"
    static let defaultHealthURL = "http://127.0.0.1:{port}/"

    var origin: CoordinatorOrigin?
    var leaseID: String?
    var agent = NSUserName()
    var project = FileManager.default.currentDirectoryPath
    var name = "web"
    var cwd = FileManager.default.currentDirectoryPath
    var executable = "npm"
    var argumentRows = ["run", "dev", "--", "--host", "127.0.0.1", "--port", "{port}"]
        .map { StartServerArgument(value: $0) }
    var range = StartServerDraft.defaultRange
    var preferredPort = ""
    var healthURL = StartServerDraft.defaultHealthURL

    var arguments: [String] {
        get { argumentRows.map(\.value) }
        set { argumentRows = newValue.map { StartServerArgument(value: $0) } }
    }
}

struct RuntimeError: LocalizedError {
    var message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

private final class SpoolBudget: @unchecked Sendable {
    private let lock = NSLock()
    private let onExceeded: @Sendable () -> Void
    private var remaining: Int
    private(set) var exceeded = false

    init(limit: Int, onExceeded: @escaping @Sendable () -> Void) {
        remaining = limit
        self.onExceeded = onExceeded
    }

    func claim(_ requested: Int) -> Int {
        let shouldSignal: Bool
        lock.lock()
        let granted = min(requested, remaining)
        remaining -= granted
        shouldSignal = granted < requested && !exceeded
        if granted < requested { exceeded = true }
        lock.unlock()
        if shouldSignal { onExceeded() }
        return granted
    }

    var isExceeded: Bool {
        lock.lock()
        defer { lock.unlock() }
        return exceeded
    }
}

private func drainPipe(_ input: FileHandle, to output: FileHandle, budget: SpoolBudget) {
    while true {
        guard let data = try? input.read(upToCount: 65_536), !data.isEmpty else { return }
        let allowed = budget.claim(data.count)
        if allowed > 0 {
            try? output.write(contentsOf: data.prefix(allowed))
        }
    }
}

private final class AsyncOneShot<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value?
    private var continuation: CheckedContinuation<Value, Never>?

    func resolve(_ value: Value) {
        let pending: CheckedContinuation<Value, Never>?
        lock.lock()
        if self.value != nil {
            lock.unlock()
            return
        }
        self.value = value
        pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }

    func wait() async -> Value {
        await withCheckedContinuation { continuation in
            lock.lock()
            if let value {
                lock.unlock()
                continuation.resume(returning: value)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }
    }
}

private final class ProcessExitLatch: @unchecked Sendable {
    private let lock = NSLock()
    private var status: Int32?
    private var waiters: [UUID: CheckedContinuation<Int32?, Never>] = [:]

    var hasExited: Bool {
        lock.lock()
        defer { lock.unlock() }
        return status != nil
    }

    func finish(_ status: Int32) {
        let pending: [CheckedContinuation<Int32?, Never>]
        lock.lock()
        if self.status != nil {
            lock.unlock()
            return
        }
        self.status = status
        pending = Array(waiters.values)
        waiters.removeAll()
        lock.unlock()
        for waiter in pending { waiter.resume(returning: status) }
    }

    func wait(timeout: TimeInterval? = nil) async -> Int32? {
        let waiterID = UUID()
        return await withCheckedContinuation { continuation in
            lock.lock()
            if let status {
                lock.unlock()
                continuation.resume(returning: status)
                return
            }
            waiters[waiterID] = continuation
            lock.unlock()
            guard let timeout else { return }
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout) { [weak self] in
                self?.expire(waiterID)
            }
        }
    }

    private func expire(_ waiterID: UUID) {
        let waiter: CheckedContinuation<Int32?, Never>?
        lock.lock()
        waiter = waiters.removeValue(forKey: waiterID)
        lock.unlock()
        waiter?.resume(returning: nil)
    }
}

private enum CommandWatchEvent: Sendable {
    case exited(Int32)
    case timedOut
    case cancelled
    case outputLimitExceeded
}

private func waitForDrain(_ group: DispatchGroup, timeout: TimeInterval) async -> Bool {
    let completion = AsyncOneShot<Bool>()
    group.notify(queue: .global(qos: .userInitiated)) {
        completion.resolve(true)
    }
    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout) {
        completion.resolve(false)
    }
    return await completion.wait()
}

actor SystemCommandExecutor: CommandExecuting {
    private let temporaryRoot: URL
    private let retainCompletedSpools: Bool
    private let baseEnvironment: [String: String]

    init(
        temporaryRoot: URL = FileManager.default.temporaryDirectory,
        retainCompletedSpools: Bool = false,
        baseEnvironment: [String: String] = CommandEnvironment.live()
    ) {
        self.temporaryRoot = temporaryRoot
        self.retainCompletedSpools = retainCompletedSpools
        self.baseEnvironment = baseEnvironment
    }

    func execute(_ request: CommandRequest) async throws -> CommandExecution {
        let root = temporaryRoot
        let retain = retainCompletedSpools
        let environment = CommandEnvironment.merging(base: baseEnvironment, overrides: request.environment)
        let worker = Task.detached(priority: .userInitiated) {
            let fileManager = FileManager.default
            let spoolDirectory = root.appendingPathComponent("devops-board-\(UUID().uuidString)", isDirectory: true)
            try fileManager.createDirectory(
                at: spoolDirectory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: spoolDirectory.path)
            let outputURL = spoolDirectory.appendingPathComponent("stdout")
            let errorURL = spoolDirectory.appendingPathComponent("stderr")
            guard fileManager.createFile(atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600]),
                  fileManager.createFile(atPath: errorURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
            else { throw RuntimeError("Unable to create private command spool files") }
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outputURL.path)
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: errorURL.path)
            defer {
                if !retain { try? fileManager.removeItem(at: spoolDirectory) }
            }

            let outputHandle = try FileHandle(forWritingTo: outputURL)
            let errorHandle = try FileHandle(forWritingTo: errorURL)
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            let watchdog = AsyncOneShot<CommandWatchEvent>()
            let budget = SpoolBudget(limit: request.maxOutputBytes) {
                watchdog.resolve(.outputLimitExceeded)
            }
            let drainGroup = DispatchGroup()
            drainGroup.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                drainPipe(outputPipe.fileHandleForReading, to: outputHandle, budget: budget)
                drainGroup.leave()
            }
            drainGroup.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                drainPipe(errorPipe.fileHandleForReading, to: errorHandle, budget: budget)
                drainGroup.leave()
            }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: request.executable)
            process.arguments = request.arguments
            process.environment = environment
            if let currentDirectory = request.currentDirectory {
                process.currentDirectoryURL = URL(fileURLWithPath: currentDirectory)
            }
            process.standardOutput = outputPipe
            process.standardError = errorPipe

            // Register completion before launch. A very short-lived command
            // can otherwise exit between run() and handler installation,
            // leaving an async waiter suspended forever.
            let processExit = ProcessExitLatch()
            process.terminationHandler = { finished in
                let status = finished.terminationStatus
                processExit.finish(status)
                watchdog.resolve(.exited(status))
            }

            do {
                try process.run()
            } catch {
                try? outputPipe.fileHandleForWriting.close()
                try? errorPipe.fileHandleForWriting.close()
                if !(await waitForDrain(drainGroup, timeout: 1)) {
                    try? outputPipe.fileHandleForReading.close()
                    try? errorPipe.fileHandleForReading.close()
                    _ = await waitForDrain(drainGroup, timeout: 1)
                }
                try? outputPipe.fileHandleForReading.close()
                try? errorPipe.fileHandleForReading.close()
                try? outputHandle.close()
                try? errorHandle.close()
                throw error
            }
            try? outputPipe.fileHandleForWriting.close()
            try? errorPipe.fileHandleForWriting.close()

            var timedOut = false
            var cancelled = false
            var outputLimitExceeded = false
            let timeout = request.timeout
            let timeoutTask = Task.detached(priority: .utility) {
                do {
                    try await Task.sleep(for: .seconds(timeout))
                    watchdog.resolve(.timedOut)
                } catch {
                    // Normal completion cancels the watchdog task.
                }
            }
            let event = await withTaskCancellationHandler {
                await watchdog.wait()
            } onCancel: {
                watchdog.resolve(.cancelled)
            }
            timeoutTask.cancel()

            let status: Int32
            switch event {
            case .exited(let exitStatus):
                status = exitStatus
            case .timedOut, .cancelled, .outputLimitExceeded:
                switch event {
                case .timedOut: timedOut = true
                case .cancelled: cancelled = true
                case .outputLimitExceeded: outputLimitExceeded = true
                case .exited: break
                }
                if !processExit.hasExited {
                    process.terminate()
                }
                if let gracefulStatus = await processExit.wait(timeout: 0.5) {
                    status = gracefulStatus
                } else {
                    // The PID belongs to the launched Process until its
                    // termination handler fires; re-check immediately before
                    // escalation to narrow the unavoidable exit/PID-reuse race.
                    if !processExit.hasExited {
                        Darwin.kill(process.processIdentifier, SIGKILL)
                    }
                    status = await processExit.wait(timeout: 5) ?? -1
                }
            }

            // Descendants can inherit a pipe after the requested process
            // exits. Bound drain completion, then close our read ends so such
            // a descendant cannot wedge command completion indefinitely.
            if !(await waitForDrain(drainGroup, timeout: 1)) {
                try? outputPipe.fileHandleForReading.close()
                try? errorPipe.fileHandleForReading.close()
                _ = await waitForDrain(drainGroup, timeout: 1)
            }
            try? outputPipe.fileHandleForReading.close()
            try? errorPipe.fileHandleForReading.close()
            try? outputHandle.synchronize()
            try? errorHandle.synchronize()
            try? outputHandle.close()
            try? errorHandle.close()

            let outputData = (try? Data(contentsOf: outputURL)) ?? Data()
            let errorData = (try? Data(contentsOf: errorURL)) ?? Data()
            let truncated = outputLimitExceeded || budget.isExceeded
            return CommandExecution(
                stdout: String(decoding: outputData, as: UTF8.self),
                stderr: String(decoding: errorData, as: UTF8.self),
                exitStatus: truncated && status == 0 ? -1 : status,
                timedOut: timedOut,
                cancelled: cancelled,
                outputTruncated: truncated
            )
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }
}

struct LocatedCoordinatorService: CoordinatorServing, Sendable {
    let executor: any CommandExecuting
    let locator: any SkillLocating

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        let service = PythonCoordinatorService(executor: executor, scriptPath: try locator.scriptPath(for: .coordinator))
        return try await service.execute(origin: origin, arguments: arguments)
    }

    func observe(origin: CoordinatorOrigin, maxAgeSeconds: Double) async throws -> CommandExecution? {
        let service = PythonCoordinatorService(executor: executor, scriptPath: try locator.scriptPath(for: .coordinator))
        return try await service.observe(origin: origin, maxAgeSeconds: maxAgeSeconds)
    }

    func requestProjectRoot() async throws -> String? {
        let service = PythonCoordinatorService(executor: executor, scriptPath: try locator.scriptPath(for: .coordinator))
        return try await service.requestProjectRoot()
    }
}

struct LocatedBackupService: BackupServing, Sendable {
    let executor: any CommandExecuting
    let locator: any SkillLocating

    func executionAuthority(
        origin: CoordinatorOrigin?,
        projectRoot: String
    ) async throws -> BackupExecutionAuthority {
        let service = PythonBackupService(executor: executor, scriptPath: try locator.scriptPath(for: .postgresBackup))
        return try await service.executionAuthority(origin: origin, projectRoot: projectRoot)
    }

    func execute(
        origin: CoordinatorOrigin?,
        projectRoot: String,
        arguments: [String]
    ) async throws -> CommandExecution {
        let service = PythonBackupService(executor: executor, scriptPath: try locator.scriptPath(for: .postgresBackup))
        return try await service.execute(origin: origin, projectRoot: projectRoot, arguments: arguments)
    }
}

struct DockerCommandPayload: Decodable, Sendable {
    let returncode: Int32?
    let stdout: String?
    let stderr: String?
}

struct BackupCommandPayload: Decodable, Sendable {
    let backup: String
    let manifest: String?
    let sha256: String?
}

struct BrokerBackupCommandPayload: Decodable, Sendable {
    let databaseBackupID: String?
    let databaseBindingID: String?
    let dockerResourceID: String?
    let databaseName: String?
    let verificationStatus: String?
    let status: String?

    enum CodingKeys: String, CodingKey {
        case status
        case databaseBackupID = "database_backup_id"
        case databaseBindingID = "database_binding_id"
        case dockerResourceID = "docker_resource_id"
        case databaseName = "database_name"
        case verificationStatus = "verification_status"
    }
}

struct BrokerRestoreCommandPayload: Decodable, Sendable {
    let restoreEventID: String?
    let databaseBackupID: String?
    let safetyDatabaseBackupID: String?
    let databaseBindingID: String?
    let dockerResourceID: String?
    let databaseName: String?
    let transactional: Bool?
    let status: String?

    enum CodingKeys: String, CodingKey {
        case transactional, status
        case restoreEventID = "restore_event_id"
        case databaseBackupID = "database_backup_id"
        case safetyDatabaseBackupID = "safety_database_backup_id"
        case databaseBindingID = "database_binding_id"
        case dockerResourceID = "docker_resource_id"
        case databaseName = "database_name"
    }
}
