import AppKit
import Darwin
import Foundation
import SwiftUI

private enum OriginInventoryExecutionResult: Sendable {
    case success(CommandExecution, databaseWarning: String?)
    case failure(String)
}

private struct OriginInventoryLoadOutcome: Sendable {
    let index: Int
    let origin: CoordinatorOrigin
    let result: OriginInventoryExecutionResult
}

private func loadOriginInventory(
    index: Int,
    origin: CoordinatorOrigin,
    arguments: [String],
    shouldEnrichBackups: Bool,
    coordinatorService: any CoordinatorServing
) async -> OriginInventoryLoadOutcome {
    do {
        let initial = try await coordinatorService.execute(origin: origin, arguments: arguments)
        guard initial.exitStatus == 0 else {
            throw RuntimeError(initial.stderr.isEmpty ? initial.stdout : initial.stderr)
        }
        let decoded = try JSONDecoder().decode(Inventory.self, from: Data(initial.stdout.utf8))
        var selected = initial
        var databaseWarning: String?
        if shouldEnrichBackups {
            let backupDirectories = Set(
                (decoded.servers.compactMap(\.project) + decoded.docker.containers.compactMap(\.project))
                    .map { URL(fileURLWithPath: $0).appendingPathComponent(".codex-db-backups").path }
            ).sorted()
            if !backupDirectories.isEmpty {
                var enrichedArguments = arguments
                for directory in backupDirectories {
                    enrichedArguments.append(contentsOf: ["--backup-dir", directory])
                }
                do {
                    let enriched = try await coordinatorService.execute(origin: origin, arguments: enrichedArguments)
                    guard enriched.exitStatus == 0 else {
                        throw RuntimeError(enriched.stderr.isEmpty ? enriched.stdout : enriched.stderr)
                    }
                    _ = try JSONDecoder().decode(Inventory.self, from: Data(enriched.stdout.utf8))
                    selected = enriched
                } catch {
                    databaseWarning = "Backup inventory incomplete: \(error.localizedDescription)"
                }
            }
        }
        return OriginInventoryLoadOutcome(
            index: index,
            origin: origin,
            result: .success(selected, databaseWarning: databaseWarning)
        )
    } catch {
        return OriginInventoryLoadOutcome(
            index: index,
            origin: origin,
            result: .failure(error.localizedDescription)
        )
    }
}

enum RefreshSurface: Hashable {
    case window
    case popover
}

@MainActor
final class OpsStore: ObservableObject {
    static let bulkStopMaximumItems = 50
    @Published var inventory: Inventory = .empty {
        didSet {
            guard oldValue != inventory else { return }
            let groups = makeProjectGroups(from: inventory)
            if groups != projectGroups { projectGroups = groups }
        }
    }
    @Published private(set) var projectGroups: [ProjectGroup] = []
    @Published var selectedServerID: ManagedServer.ID?
    @Published var selectedDockerID: String?
    @Published var selectedDatabaseID: String?
    @Published var selectedProjectName: String?
    @Published var sidebarSelection: SidebarSelection?
    @Published var activeTab: ResourceTab = .servers
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
    @Published var inventoryIssue: OpsIssue?
    @Published var actionIssue: OpsIssue?

    private let coordinatorService: any CoordinatorServing
    private let backupService: any BackupServing
    private let commandExecutor: any CommandExecuting
    private let databaseDiscovery: any DatabaseDiscovering
    private let originDiscovery: any CoordinatorOriginDiscovering
    private let configurationStore: any CoordinatorConfigurationPersisting
    private let clock: any Clock
    private var lastErrorSource: String?
    private var inventoryByOrigin: [String: Inventory] = [:]
    private var lastInventoryAttemptAt: Date?
    private var visibleSurfaces: Set<RefreshSurface> = []
    private var autoRefreshTask: Task<Void, Never>?
    private var activeLoad: Task<Void, Never>?
    private var followUpRequested = false
    private var verifiedBackupsByKey: [String: BackupRecord] = [:]
    private var backupVerificationTasks: [String: Task<Void, Never>] = [:]

    init(
        coordinatorService: (any CoordinatorServing)? = nil,
        backupService: (any BackupServing)? = nil,
        commandExecutor: (any CommandExecuting)? = nil,
        databaseDiscovery: (any DatabaseDiscovering)? = nil,
        originDiscovery: any CoordinatorOriginDiscovering = FileSystemCoordinatorOriginDiscovery(),
        configurationStore: any CoordinatorConfigurationPersisting = PrivateCoordinatorConfigurationStore(),
        clock: any Clock = SystemClock(),
        skillLocator: any SkillLocating = PortableSkillLocator()
    ) {
        let executor = commandExecutor ?? SystemCommandExecutor()
        self.commandExecutor = executor
        self.databaseDiscovery = databaseDiscovery ?? DockerPostgresDiscoveryService(executor: executor)
        self.originDiscovery = originDiscovery
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

    var selectedServer: ManagedServer? {
        guard let selectedServerID else { return nil }
        return inventory.servers.first { $0.id == selectedServerID }
    }

    var selectedDocker: DockerContainer? {
        guard let selectedDockerID else { return nil }
        return inventory.docker.containers.first { $0.stableID == selectedDockerID }
    }

    var selectedDatabase: DockerContainer? {
        guard let selectedDatabaseID else { return nil }
        return inventory.postgres.first { $0.stableID == selectedDatabaseID }
    }

    var filteredServers: [ManagedServer] {
        inventory.servers.filter { server in
            let status = (server.status ?? "").lowercased()
            let matchesFilter: Bool
            switch filter {
            case .all:
                matchesFilter = true
            case .running:
                matchesFilter = status == "running"
            case .unhealthy:
                matchesFilter = status == "unhealthy" || status == "degraded" || server.health?.ok == false
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

    var visibleDockerContainers: [DockerContainer] {
        filterDocker(inventory.docker.containers)
    }

    var visiblePostgres: [DockerContainer] {
        filterDocker(inventory.postgres)
    }

    var connected: Bool {
        sourceStates.contains { $0.phase == .loaded }
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
            capabilities: capabilityStates
        )
    }

    var refreshIntervalSeconds: Double? {
        coordinatorConfiguration.refreshPolicy.mode == .interval
            ? coordinatorConfiguration.refreshPolicy.intervalSeconds
            : nil
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
        if visible {
            visibleSurfaces.insert(surface)
        } else {
            visibleSurfaces.remove(surface)
        }
        if visibleSurfaces.isEmpty {
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

    private func reportMissingOwnership(_ action: String) {
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
        let origins = Set(
            group.servers.compactMap(\.origin)
                + group.containers.compactMap(\.origin)
                + group.databases.compactMap(\.origin)
                + [group.usage?.origin].compactMap { $0 }
        )
        guard origins.count == 1, let origin = origins.first else {
            return .blocked(.invalidResource, "The project does not have exactly one owning coordinator source")
        }
        let identity = ResourceIdentity(origin: origin, kind: .project, nativeID: projectPath)
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
             .leasePort, .releasePort,
             .projectStatus, .projectStart, .projectStop, .projectRestart:
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

    private var resourceHealthSignals: [ResourceHealthSignal] {
        var signals: [ResourceHealthSignal] = inventory.servers.compactMap { server in
            guard let identity = server.resourceIdentity else { return nil }
            let status = (server.status ?? "unknown").lowercased()
            guard server.health?.ok == false || ["unhealthy", "degraded", "orphaned"].contains(status) else { return nil }
            return ResourceHealthSignal(identity: identity, level: .unhealthy, reason: server.stoppedReason ?? status)
        }
        signals.append(contentsOf: inventory.docker.containers.compactMap { container in
            guard let identity = container.resourceIdentity else { return nil }
            let status = (container.status ?? "unknown").lowercased()
            guard status.contains("unhealthy") || status.contains("dead") || status.contains("restart") else { return nil }
            return ResourceHealthSignal(identity: identity, level: .unhealthy, reason: status)
        })
        return signals
    }

    @discardableResult
    func saveCoordinatorConfiguration(_ configuration: CoordinatorConfiguration) -> Bool {
        do {
            let validated = try configuration.validated()
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
            return
        }
        sourceStates = origins.map { CoordinatorSourceState(origin: $0, phase: .loading, checkedAt: clock.now()) }
        capabilityStates = origins.flatMap { origin in
            CoordinatorCapability.allCases.map {
                CoordinatorCapabilityState(
                    origin: origin,
                    capability: $0,
                    phase: .loading,
                    checkedAt: clock.now(),
                    error: nil
                )
            }
        }
        let projectScope = scopedProjectPath
        let arguments = projectScope.map { ["inventory", "--project", $0] } ?? ["inventory"]
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
                        shouldEnrichBackups: projectScope == nil,
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
        var capabilityFailures: [String] = []
        for outcome in outcomes {
            let origin = outcome.origin
            var decoded: Inventory?
            var databaseWarning: String?
            var sourceFailure: String?
            switch outcome.result {
            case .success(let result, let warning):
                do {
                    decoded = try JSONDecoder().decode(Inventory.self, from: Data(result.stdout.utf8))
                    databaseWarning = warning
                } catch {
                    sourceFailure = error.localizedDescription
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
                if let dockerWarning {
                    databaseWarning = "Database capability unavailable because \(dockerWarning.lowercased())"
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
            } else {
                let retained = inventoryByOrigin[origin.id]
                let phase: CoordinatorSourcePhase = retained == nil ? .failed : .stale
                let resourceCount = retained.map { $0.servers.count + $0.leases.count + $0.docker.containers.count + $0.postgres.count } ?? 0
                let failure = sourceFailure ?? "Coordinator inventory unavailable"
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
        var decoded = mergeInventories(origins.compactMap { inventoryByOrigin[$0.id] })
        decoded.servers = deduplicatedManagedServers(decoded.servers)
        decoded = await discoverDatabases(in: decoded)
        if decoded != inventory { inventory = decoded }
        rebuildBackupRecords(from: decoded.backups)
        reconcileLeaseResults(now: clock.now())
        keepSelectionValid()
        if let selectedDatabase {
            requestBackupVerification(for: selectedDatabase)
        }
        if sourceFailures.isEmpty && capabilityFailures.isEmpty {
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
            let details = ([configurationWarning] + sourceFailures.map(Optional.some) + capabilityFailures.map(Optional.some))
                .compactMap { $0 }
                .joined(separator: "\n")
            setLastError(
                title: "Inventory incomplete",
                summary: "\(sourceFailures.count) coordinator source\(sourceFailures.count == 1 ? "" : "s") could not be refreshed",
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
        return result
    }

    private func discoverDatabases(in inventory: Inventory) async -> Inventory {
        var result = inventory
        var databases: [DockerContainer] = []
        for container in inventory.postgres {
            guard let origin = container.origin, container.ownershipError == nil else {
                var unavailable = container
                unavailable.databaseDiscoveryError = container.ownershipError ?? "coordinator ownership is unavailable"
                databases.append(unavailable)
                continue
            }
            guard container.isRunning else {
                var unavailable = container
                unavailable.databaseDiscoveryError = "container is not running"
                databases.append(unavailable)
                continue
            }
            guard let name = container.name, !name.isEmpty else {
                var unavailable = container
                unavailable.databaseDiscoveryError = "container identity is unavailable"
                databases.append(unavailable)
                continue
            }
            do {
                let discovered = try await databaseDiscovery.discover(origin: origin, container: name, containerID: container.id)
                if discovered.isEmpty {
                    var unavailable = container
                    unavailable.databaseDiscoveryError = "no connectable databases were returned"
                    databases.append(unavailable)
                } else {
                    databases.append(contentsOf: discovered.map { database in
                        var row = container
                        row.database = database.identity.database
                        row.databaseSizeBytes = database.sizeBytes
                        row.databaseDiscoveryError = nil
                        return row
                    })
                }
            } catch {
                var unavailable = container
                unavailable.databaseDiscoveryError = error.localizedDescription
                databases.append(unavailable)
            }
        }
        result.postgres = databases
        return result
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
        first.postgres = reconcileDockerOwnership(inventories.flatMap(\.postgres))
        first.backups = inventories.flatMap(\.backups)
        first.projectUsage = mergeProjectUsage(inventories.flatMap(\.projectUsage))
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
        let containers = reconcileDockerOwnership(summaries.flatMap(\.containers))
        let postgres = reconcileDockerOwnership(summaries.flatMap(\.postgres))
        return DockerSummary(available: available, error: error, statsError: statsError, containers: containers, postgres: postgres)
    }

    private func reconcileDockerOwnership(_ containers: [DockerContainer]) -> [DockerContainer] {
        let grouped = Dictionary(grouping: containers) { container in
            container.id ?? "name:\(container.name ?? "unknown")"
        }
        return grouped.values.compactMap { bucket in
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
                conflict.ownershipCandidates = sidecarOwners.values.compactMap { $0.first?.origin }.sorted { $0.id < $1.id }
                conflict.ownershipError = "conflicting coordinator-sidecar ownership"
                conflict.origin = nil
                return conflict
            }
            let composeOwned = bucket.filter {
                $0.metadataSource == "docker_labels" && $0.project?.isEmpty == false && $0.origin != nil
            }
            if let selected = composeOwned.sorted(by: { ($0.origin?.id ?? "") < ($1.origin?.id ?? "") }).first {
                var selected = selected
                selected.ownershipCandidates = composeOwned.compactMap(\.origin)
                return selected
            }
            guard var unknown = bucket.max(by: { dockerContainerRank($0) < dockerContainerRank($1) }) else { return nil }
            unknown.ownershipCandidates = bucket.compactMap(\.origin)
            unknown.ownershipError = "no coordinator or Docker Compose ownership metadata"
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
            // Membership must merge as a union: each coordinator home only
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
        actionIssue = nil
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
        if !result.stdout.isEmpty { lines.append("Stdout:\n\(result.stdout)") }
        if !result.stderr.isEmpty { lines.append("Stderr:\n\(result.stderr)") }
        if result.outputTruncated { lines.append("Output was truncated by the bounded executor.") }
        return lines.joined(separator: "\n")
    }

    func copyActionResultDetails(_ result: RetainedActionResult) {
        let detail = actionResultDetails(result)
        guard !detail.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(detail, forType: .string)
    }

    func dismissActionResult(_ result: RetainedActionResult) {
        guard result.phase != .queued && result.phase != .running else { return }
        actionResults.removeValue(forKey: result.id)
        if actionIssue?.relatedActionID == result.id {
            clearActionErrorIfPresent(actionID: result.id)
        }
    }

    func clearLastError() {
        if lastErrorSource == "action" { actionIssue = nil }
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
        actionIssue = nil
        if lastErrorSource == "action" { clearLegacyError() }
    }

    func selectProject(_ name: String) {
        selectedProjectName = name
        sidebarSelection = .project(name)
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

    func selectServer(_ server: ManagedServer) {
        activeTab = .servers
        selectedServerID = server.id
        sidebarSelection = .server(server.id)
    }

    func selectDocker(_ container: DockerContainer) {
        activeTab = .docker
        selectedDockerID = container.stableID
        sidebarSelection = .docker(container.stableID)
    }

    func selectDatabase(_ container: DockerContainer) {
        activeTab = .databases
        selectedDatabaseID = container.stableID
        sidebarSelection = .database(container.stableID)
        requestBackupVerification(for: container)
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
            return (backup, record)
        }
        guard let candidate = candidates.max(by: { $0.record.createdAt < $1.record.createdAt }) else { return }
        let key = candidate.backup.verificationCacheKey
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
        guard let origin = server.origin, let identity = server.resourceIdentity, let project = server.project else {
            reportMissingOwnership("Restart \(server.name)")
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
        guard let origin = server.origin, let identity = server.resourceIdentity, let project = server.project else {
            reportMissingOwnership("Stop \(server.name)")
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
                details: "Only an active, unbound manual lease with exact agent and project ownership can start a server. Lease: \(lease.leaseID)",
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
                details: "Only an active, unbound lease with exact project ownership can be released directly. Stop an attached server through its server action.",
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

    func backupDatabase(container: DockerContainer?) {
        guard let container,
              let origin = container.origin,
              let identity = container.databaseIdentity,
              let containerID = identity.containerID,
              let project = container.project,
              !project.isEmpty
        else {
            setLastError(
                title: "Backup database failed",
                summary: "Select an exact discovered database with a known project and coordinator source",
                details: "A container alone is not a database identity. Refresh discovery and choose a concrete database before backup.",
                source: "action"
            )
            return
        }
        let args = [
            "backup",
            "--out-dir", "\(project)/.codex-db-backups",
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
        let safetyDirectory = URL(fileURLWithPath: backup.path)
            .deletingLastPathComponent()
            .appendingPathComponent("pre-restore", isDirectory: true)
            .path
        let arguments = [
            "restore",
            "--container", target.container,
            "--database", target.database,
            "--file", backup.path,
            "--expect-container-id", targetContainerID,
            "--confirm-restore",
            "--safety-out-dir", safetyDirectory,
        ]
        Task {
            markActionRunning(request.id)
            var retainedExecution: CommandExecution?
            do {
                let execution = try await backupService.execute(origin: target.origin, arguments: arguments)
                retainedExecution = execution
                if execution.exitStatus == 0 {
                    let evidence = try validatedRestoreEvidence(
                        execution: execution,
                        target: target,
                        backup: backup,
                        actionID: request.id
                    )
                    restoreEvidence[target] = evidence
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
            reportMissingOwnership("Docker logs")
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
            reportMissingOwnership("Restart container")
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
            reportMissingOwnership("Start container")
            return
        }
        runTracked(title: "Start container", subtitle: name, kind: .startDocker, origin: origin, resource: identity, arguments: ["docker", "start", "--agent", agentID, "--project", project, "--container", name])
    }

    func stopDocker(_ container: DockerContainer) {
        guard let name = container.name, let origin = container.origin, let identity = container.resourceIdentity, let project = container.project else {
            reportMissingOwnership("Stop container")
            return
        }
        runTracked(title: "Stop container", subtitle: name, kind: .stopDocker, origin: origin, resource: identity, arguments: ["docker", "stop", "--agent", agentID, "--project", project, "--container", name])
    }

    func showServerLogs(_ server: ManagedServer) {
        guard let origin = server.origin, let identity = server.resourceIdentity, let project = server.project else {
            reportMissingOwnership("Server logs")
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
                let status = (container.status ?? "").lowercased()
                matchesFilter = status.contains("restart") || status.contains("unhealthy") || status.contains("dead")
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
        if let selectedServerID, !inventory.servers.contains(where: { $0.id == selectedServerID }) {
            self.selectedServerID = nil
        }
        if let selectedDockerID, !inventory.docker.containers.contains(where: { $0.stableID == selectedDockerID }) {
            self.selectedDockerID = nil
        }
        if let selectedDatabaseID, !inventory.postgres.contains(where: { $0.stableID == selectedDatabaseID }) {
            self.selectedDatabaseID = nil
        }
        if selectedServerID == nil, selectedDockerID == nil, selectedDatabaseID == nil {
            if let fallback = inventory.servers.first?.id {
                selectedServerID = fallback
                sidebarSelection = .server(fallback)
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
        arguments: [String]
    ) {
        guard requireMutationAvailability(title: title, kind: .backupDatabase, origin: origin, resource: resource) else { return }
        let request = beginAction(kind: .backupDatabase, title: title, origin: origin, resource: resource)
        Task {
            markActionRunning(request.id)
            var retainedExecution: CommandExecution?
            do {
                let backup = try await backupService.execute(origin: origin, arguments: arguments)
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
                let payload = try JSONDecoder().decode(BackupCommandPayload.self, from: Data(backup.stdout.utf8))
                let verifyArguments = [
                    "verify",
                    "--container", container,
                    "--database", database,
                    "--file", payload.backup,
                    "--expect-container-id", containerID,
                    "--test-restore",
                ]
                let verification = try await backupService.execute(origin: origin, arguments: verifyArguments)
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
        let origins = Set(
            group.servers.compactMap(\.origin)
                + group.containers.compactMap(\.origin)
                + group.databases.compactMap(\.origin)
                + [group.usage?.origin].compactMap { $0 }
        )
        guard origins.count == 1, let origin = origins.first else {
            reportAmbiguousSource("Project runtime \(action)")
            return
        }
        let kind: ActionKind = switch action {
        case "start": .projectStart
        case "restart": .projectRestart
        case "stop": .projectStop
        default: .projectStatus
        }
        let identity = ResourceIdentity(origin: origin, kind: .project, nativeID: projectPath)
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
            actionIssue = issue
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
}

struct LocatedBackupService: BackupServing, Sendable {
    let executor: any CommandExecuting
    let locator: any SkillLocating

    func execute(origin: CoordinatorOrigin?, arguments: [String]) async throws -> CommandExecution {
        let service = PythonBackupService(executor: executor, scriptPath: try locator.scriptPath(for: .postgresBackup))
        return try await service.execute(origin: origin, arguments: arguments)
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
