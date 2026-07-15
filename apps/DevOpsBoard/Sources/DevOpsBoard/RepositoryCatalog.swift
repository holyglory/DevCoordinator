import Foundation

private func normalizedAbsoluteProjectPath(_ projectPath: String?) -> String? {
    guard let projectPath else { return nil }
    let trimmed = projectPath.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.hasPrefix("/") else { return nil }
    let normalized = URL(fileURLWithPath: trimmed, isDirectory: true)
        .standardizedFileURL
        .resolvingSymlinksInPath()
        .path
    return normalized == "/" ? nil : normalized
}

/// Resolve only existing Git worktrees. Path-shaped legacy evidence is kept by
/// the catalog as unassigned evidence; it must not manufacture an active
/// repository merely because an old record contains an absolute path.
private func verifiedGitWorktreeRoot(_ projectPath: String?) -> String? {
    guard let normalized = normalizedAbsoluteProjectPath(projectPath) else { return nil }
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: normalized, isDirectory: &isDirectory) else { return nil }

    var candidate = isDirectory.boolValue
        ? URL(fileURLWithPath: normalized, isDirectory: true)
        : URL(fileURLWithPath: normalized).deletingLastPathComponent()
    while candidate.path != "/" {
        if FileManager.default.fileExists(
            atPath: candidate.appendingPathComponent(".git").path
        ) {
            return candidate.standardizedFileURL.resolvingSymlinksInPath().path
        }
        candidate.deleteLastPathComponent()
    }
    return nil
}

/// A local repository is identified only by its canonical worktree root.
/// Source homes and display labels are observation provenance, not identity.
struct RepositoryIdentity: Hashable, Sendable, Identifiable, Comparable {
    /// Durable normalized identity. Legacy/test catalogs do not have one and
    /// fall back to the canonical root, but production v2 projections always
    /// populate this field from `repositories.repo_id`.
    let repoID: String?
    let canonicalRoot: String
    private let authoritativeDisplayName: String?

    init?(projectPath: String?) {
        guard let root = verifiedGitWorktreeRoot(projectPath) else { return nil }
        self.repoID = nil
        self.canonicalRoot = root
        self.authoritativeDisplayName = nil
    }

    init(repoID: String, canonicalRoot: String, displayName: String? = nil) {
        self.repoID = repoID
        self.canonicalRoot = canonicalRoot
        let candidate = displayName?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.authoritativeDisplayName = candidate?.isEmpty == false ? candidate : nil
    }

    var id: String { repoID ?? canonicalRoot }
    var displayName: String {
        authoritativeDisplayName ?? URL(fileURLWithPath: canonicalRoot).lastPathComponent
    }

    static func == (lhs: RepositoryIdentity, rhs: RepositoryIdentity) -> Bool {
        lhs.repoID == rhs.repoID && lhs.canonicalRoot == rhs.canonicalRoot
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(repoID)
        hasher.combine(canonicalRoot)
    }

    static func < (lhs: RepositoryIdentity, rhs: RepositoryIdentity) -> Bool {
        lhs.canonicalRoot < rhs.canonicalRoot
    }
}

/// The immutable source boundary used to build one repository catalog.
struct RepositoryInventorySource: Equatable, Sendable {
    let origin: CoordinatorOrigin
    let inventory: Inventory
}

struct RepositoryServerObservation: Equatable, Sendable, Identifiable {
    let sourceIdentity: ResourceIdentity
    let server: ManagedServer

    var id: ResourceIdentity { sourceIdentity }
}

struct RepositoryDockerObservation: Equatable, Sendable, Identifiable {
    let sourceIdentity: ResourceIdentity
    let container: DockerContainer

    var id: ResourceIdentity { sourceIdentity }
}

struct RepositoryLogicalServerIdentity: Hashable, Sendable, Identifiable, Comparable {
    let repository: RepositoryIdentity
    let serviceKey: String

    init(repository: RepositoryIdentity, serviceName: String) {
        self.repository = repository
        self.serviceKey = serviceName
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    var id: String { "\(repository.id)|server|\(serviceKey)" }

    static func < (lhs: RepositoryLogicalServerIdentity, rhs: RepositoryLogicalServerIdentity) -> Bool {
        lhs.id < rhs.id
    }
}

struct RepositoryServerConflict: Equatable, Sendable, Identifiable {
    let service: RepositoryLogicalServerIdentity
    let activeSourceIdentities: [ResourceIdentity]

    var id: String { service.id }
    var message: String {
        "Several active coordinator records claim \(service.serviceKey) for one repository, but their process endpoints differ."
    }
}

struct RepositoryServerMembershipConflict: Equatable, Sendable, Identifiable {
    let id: String
    let repositories: [RepositoryIdentity]
    let activeSourceIdentities: [ResourceIdentity]
    let claimedPaths: [String]

    var message: String {
        "One server resource is claimed by several repository paths. Resolve its ownership before acting."
    }
}

/// One logical repository service with every source observation preserved.
/// A simultaneous multi-process conflict remains one row but blocks routing.
struct RepositoryManagedServer: Equatable, Sendable, Identifiable {
    let identity: RepositoryLogicalServerIdentity
    let representative: ManagedServer
    let observations: [RepositoryServerObservation]
    let conflict: RepositoryServerConflict?
    let membershipConflicts: [RepositoryServerMembershipConflict]
    let controlCandidates: [CoordinatorOrigin]
    let actionOrigin: CoordinatorOrigin?

    var id: String { identity.id }
    var sourceIdentities: [ResourceIdentity] { observations.map(\.sourceIdentity) }
    var sourceOrigins: Set<CoordinatorOrigin> { Set(observations.map { $0.sourceIdentity.origin }) }
    var isActionBlocked: Bool { conflict != nil || !membershipConflicts.isEmpty || actionOrigin == nil }
}

struct RepositoryDockerIdentity: Codable, Hashable, Sendable, Identifiable, Comparable {
    let rawValue: String
    let isImmutable: Bool

    var id: String { rawValue }

    static func < (lhs: RepositoryDockerIdentity, rhs: RepositoryDockerIdentity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

struct RepositoryDockerMembershipConflict: Equatable, Sendable, Identifiable {
    let resource: RepositoryDockerIdentity
    let repositories: [RepositoryIdentity]
    let sourceIdentities: [ResourceIdentity]
    let claimedPaths: [String]

    var id: String { resource.id }
    var message: String {
        "One physical Docker container is claimed by several repository paths. Resolve its ownership before acting."
    }
}

/// One physical Docker container. Observations from several coordinator homes
/// remain available for provenance and resource-level action routing.
struct RepositoryDockerResource: Equatable, Sendable, Identifiable {
    let identity: RepositoryDockerIdentity
    let representative: DockerContainer
    let observations: [RepositoryDockerObservation]
    let repositoryCandidates: [RepositoryIdentity]
    let membershipError: String?
    let controlCandidates: [CoordinatorOrigin]

    var id: String { identity.id }
    var sourceIdentities: [ResourceIdentity] { observations.map(\.sourceIdentity) }
    var sourceOrigins: Set<CoordinatorOrigin> { Set(observations.map { $0.sourceIdentity.origin }) }
}

struct RepositorySourceObservation: Equatable, Sendable, Identifiable {
    let repository: RepositoryIdentity
    let origin: CoordinatorOrigin
    let displayLabels: [String]
    let usageRows: [ProjectUsage]
    let serverIdentities: [ResourceIdentity]
    let dockerIdentities: [ResourceIdentity]

    var id: String { "\(repository.id)|source|\(origin.id)" }
}

struct RepositoryUsage: Equatable, Sendable {
    let serverCount: Int
    let containerCount: Int
    let processCount: Int
    let cpuPercent: Double
    let memoryBytes: Double
    let hotProcesses: [ProcessUsage]
}

struct RepositoryAggregate: Equatable, Sendable, Identifiable {
    let identity: RepositoryIdentity
    let observedLabels: [String]
    let sourceObservations: [RepositorySourceObservation]
    let servers: [RepositoryManagedServer]
    let docker: [RepositoryDockerResource]
    let usage: RepositoryUsage
    let controlOrigin: CoordinatorOrigin?
    let serverMembershipConflicts: [RepositoryServerMembershipConflict]
    let dockerMembershipConflicts: [RepositoryDockerMembershipConflict]

    var id: String { identity.id }
    var displayName: String { identity.displayName }
    var serverConflicts: [RepositoryServerConflict] { servers.compactMap(\.conflict) }
    var projectActionsBlocked: Bool {
        controlOrigin == nil
            || !serverConflicts.isEmpty
            || !serverMembershipConflicts.isEmpty
            || !dockerMembershipConflicts.isEmpty
    }
}

/// Resources without a canonical repository never become name-derived
/// projects. They remain visible together in this explicit aggregate.
struct UnassignedResources: Equatable, Sendable {
    let servers: [RepositoryServerObservation]
    let docker: [RepositoryDockerResource]
    let usageObservations: [ProjectUsage]

    static let empty = UnassignedResources(servers: [], docker: [], usageObservations: [])
}

struct RepositoryCatalog: Equatable, Sendable {
    let repositories: [RepositoryAggregate]
    let unassigned: UnassignedResources

    static let empty = RepositoryCatalog(repositories: [], unassigned: .empty)

    static func build(from sources: [RepositoryInventorySource]) -> RepositoryCatalog {
        RepositoryCatalogBuilder(sources: sources).build()
    }

    /// Test/snapshot and cached-presentation adapter. Production refreshes
    /// build from the original per-source inventories before flattening so no
    /// provenance is lost; this overload reconstructs those source slices
    /// from the origin attached to each decoded row.
    static func build(from inventory: Inventory) -> RepositoryCatalog {
        build(from: repositoryInventorySources(from: inventory))
    }
}

enum ProjectGroupKind: String, Equatable, Sendable {
    case repository
    case unassigned
}

/// The UI read model for one repository aggregate (or the single explicit
/// unassigned-resources bucket). Repository identity and action provenance are
/// intentionally separate: `id`/`projectPath` never include a source home,
/// while every resource retains its source-qualified identity.
struct ProjectGroup: Equatable {
    var id: String
    var name: String
    var projectPath: String?
    var repositoryID: String? = nil
    var servers: [ManagedServer]
    var containers: [DockerContainer]
    var databases: [DockerContainer]
    var usage: ProjectUsage?
    var kind: ProjectGroupKind = .repository
    var controlOrigin: CoordinatorOrigin? = nil
    var observedOrigins: [CoordinatorOrigin] = []
    var serverConflicts: [RepositoryServerConflict] = []
    var serverMembershipConflicts: [RepositoryServerMembershipConflict] = []
    var dockerMembershipConflicts: [RepositoryDockerMembershipConflict] = []
    var unassignedEvidenceCount = 0
    var usesCatalogControlBinding = false

    var hasObservedDockerRuntime: Bool {
        !containers.isEmpty
            || !databases.isEmpty
            || !dockerMembershipConflicts.isEmpty
            || (usage?.containerCount ?? 0) > 0
    }

    var isRepository: Bool { kind == .repository }
    var projectActionsBlocked: Bool {
        actionOrigin == nil
            || !serverConflicts.isEmpty
            || !serverMembershipConflicts.isEmpty
            || !dockerMembershipConflicts.isEmpty
    }

    /// Existing focused tests and hand-built fixtures predate the catalog and
    /// still carry one unambiguous origin directly on their resources. Live
    /// catalog groups use the explicit binding, including an intentional nil
    /// when several legacy sources cannot be routed safely.
    var actionOrigin: CoordinatorOrigin? {
        if usesCatalogControlBinding { return controlOrigin }
        let origins = Set(
            servers.compactMap(\.origin)
                + containers.compactMap(\.origin)
                + databases.compactMap(\.origin)
                + [usage?.origin].compactMap { $0 }
        )
        return origins.count == 1 ? origins.first : nil
    }
}

let unassignedProjectGroupID = "unassigned-resources"

func makeProjectGroups(from inventory: Inventory) -> [ProjectGroup] {
    makeProjectGroups(from: RepositoryCatalog.build(from: inventory), inventory: inventory)
}

func makeProjectGroups(from catalog: RepositoryCatalog, inventory: Inventory) -> [ProjectGroup] {
    let repositoryDockerIDs = Set(
        catalog.repositories.flatMap(\.docker).compactMap { repositoryDockerNativeID($0.representative) }
    )
    var groups = catalog.repositories.map { aggregate in
        let repositoryContainerIDs = Set(
            aggregate.docker.compactMap { repositoryDockerNativeID($0.representative) }
        )
        let physicalContainers = aggregate.docker.map { resource -> DockerContainer in
            repositoryDockerPresentation(resource, inventory: inventory)
        }
        let servers = aggregate.servers.map { service -> ManagedServer in
            var server = service.representative
            server.ownershipCandidates = Array(service.sourceOrigins).sorted { $0.id < $1.id }
            server.observationOrigins = service.sourceOrigins.sorted { $0.id < $1.id }
            if let actionOrigin = service.actionOrigin {
                server.origin = actionOrigin
            }
            server.ownershipError = service.conflict?.message
                ?? service.membershipConflicts.first?.message
                ?? (service.actionOrigin == nil
                    ? "Several coordinator sources retain this server definition; choose an authoritative source before acting."
                    : nil)
            return server
        }
        let databases = inventory.postgres
            .filter { database in
                if let nativeID = repositoryDockerNativeID(database), repositoryContainerIDs.contains(nativeID) {
                    return true
                }
                return RepositoryIdentity(projectPath: database.project) == aggregate.identity
            }
            .map { database -> DockerContainer in
                guard let nativeID = repositoryDockerNativeID(database),
                      let physical = physicalContainers.first(where: { repositoryDockerNativeID($0) == nativeID })
                else { return database }
                var database = database
                if database.origin == nil { database.origin = physical.origin }
                if database.ownershipCandidates.isEmpty {
                    database.ownershipCandidates = physical.ownershipCandidates
                }
                if database.ownershipError == nil { database.ownershipError = physical.ownershipError }
                database.observationOrigins = physical.observationOrigins
                return database
            }

        var usage = ProjectUsage(
            usageKey: "path:\(aggregate.identity.canonicalRoot)",
            project: aggregate.identity.canonicalRoot,
            projectKey: aggregate.displayName.lowercased(),
            name: aggregate.displayName,
            serverIDs: servers.map { $0.coordinatorID ?? $0.id },
            containerNames: physicalContainers.compactMap(\.name),
            serverCount: aggregate.usage.serverCount,
            containerCount: aggregate.usage.containerCount,
            processCount: aggregate.usage.processCount,
            cpuPercent: aggregate.usage.cpuPercent,
            memoryBytes: aggregate.usage.memoryBytes,
            processCPUPercent: nil,
            processMemoryBytes: nil,
            dockerCPUPercent: nil,
            dockerMemoryBytes: nil,
            processes: nil,
            hotProcesses: aggregate.usage.hotProcesses
        )
        usage.origin = aggregate.controlOrigin
        return ProjectGroup(
            id: aggregate.identity.repoID.map { "repo:\($0)" }
                ?? "path:\(aggregate.identity.canonicalRoot)",
            name: aggregate.displayName,
            projectPath: aggregate.identity.canonicalRoot,
            repositoryID: aggregate.identity.repoID,
            servers: servers,
            containers: physicalContainers.filter { !$0.isPostgresLike },
            databases: databases,
            usage: usage,
            kind: .repository,
            controlOrigin: aggregate.controlOrigin,
            observedOrigins: aggregate.sourceObservations.map(\.origin),
            serverConflicts: aggregate.serverConflicts,
            serverMembershipConflicts: aggregate.serverMembershipConflicts,
            dockerMembershipConflicts: aggregate.dockerMembershipConflicts,
            usesCatalogControlBinding: true
        )
    }

    let unassignedDocker = catalog.unassigned.docker.map { resource -> DockerContainer in
        repositoryDockerPresentation(resource, inventory: inventory)
    }
    let unassignedContainerIDs = Set(unassignedDocker.compactMap(repositoryDockerNativeID))
    let unassignedDatabases = inventory.postgres.filter { database in
        guard let nativeID = repositoryDockerNativeID(database) else {
            return RepositoryIdentity(projectPath: database.project) == nil
        }
        return unassignedContainerIDs.contains(nativeID)
            || (!repositoryDockerIDs.contains(nativeID)
                && RepositoryIdentity(projectPath: database.project) == nil)
    }
    let unassignedServers = unassignedServerPresentations(catalog.unassigned.servers)
    if !unassignedServers.isEmpty
        || !unassignedDocker.isEmpty
        || !unassignedDatabases.isEmpty
        || !catalog.unassigned.usageObservations.isEmpty {
        let origins = Set(
            catalog.unassigned.servers.map { $0.sourceIdentity.origin }
                + catalog.unassigned.docker.flatMap { Array($0.sourceOrigins) }
                + catalog.unassigned.usageObservations.compactMap(\.origin)
        )
        groups.append(
            ProjectGroup(
                id: unassignedProjectGroupID,
                name: "Unassigned Resources",
                projectPath: nil,
                servers: unassignedServers,
                containers: unassignedDocker.filter { !$0.isPostgresLike },
                databases: unassignedDatabases,
                usage: nil,
                kind: .unassigned,
                controlOrigin: nil,
                observedOrigins: origins.sorted { $0.id < $1.id },
                serverConflicts: [],
                unassignedEvidenceCount: catalog.unassigned.usageObservations.count,
                usesCatalogControlBinding: true
            )
        )
    }

    return groups.sorted { lhs, rhs in
        if lhs.kind != rhs.kind { return lhs.kind == .repository }
        return (lhs.name.lowercased(), lhs.id) < (rhs.name.lowercased(), rhs.id)
    }
}

private func unassignedServerPresentations(
    _ observations: [RepositoryServerObservation]
) -> [ManagedServer] {
    let active = observations.filter { isActiveServerObservation($0.server) }
    let activeIdentities = Set(active.map(\.sourceIdentity))
    let stoppedOrUnknown = observations.filter { !activeIdentities.contains($0.sourceIdentity) }
        .map { observation -> ManagedServer in
            var server = observation.server
            server.observationOrigins = [observation.sourceIdentity.origin]
            if server.ownershipCandidates.isEmpty {
                server.ownershipCandidates = [observation.sourceIdentity.origin]
            }
            return server
        }
    let activePhysical = physicalServerGroups(active).map { group -> ManagedServer in
        let ranked = group.max { serverObservationRank($0) < serverObservationRank($1) }!
        var server = ranked.server
        let origins = Set(group.map { $0.sourceIdentity.origin }).sorted { $0.id < $1.id }
        server.observationOrigins = origins
        server.ownershipCandidates = origins
        server.ownershipError = group.compactMap { $0.server.ownershipError }.first
        return server
    }
    return deduplicatedManagedServers(activePhysical + stoppedOrUnknown)
        .sorted { ($0.name.lowercased(), $0.id) < ($1.name.lowercased(), $1.id) }
}

func projectMembershipKey(originID: String?, nativeID: String) -> String {
    "\(originID ?? "unknown")|\(nativeID)"
}

/// Compatibility helper for persisted sidebar selections and the standalone
/// geometry executable. The origin is intentionally ignored for repository
/// paths: one canonical root must always produce one project group.
func projectGroupID(originID _: String?, usageKey: String) -> String {
    guard usageKey.hasPrefix("path:") else { return unassignedProjectGroupID }
    return usageKey
}

func strayProjectGroupID(originID _: String?) -> String {
    unassignedProjectGroupID
}

func repositoryCatalogConflictHealthSignals(_ catalog: RepositoryCatalog) -> [ResourceHealthSignal] {
    var signals: [String: ResourceHealthSignal] = [:]

    func append(id: String, origins: [CoordinatorOrigin], reason: String) {
        guard let origin = Set(origins).sorted(by: { $0.id < $1.id }).first else { return }
        let identity = ResourceIdentity(
            origin: origin,
            kind: .project,
            nativeID: "repository-catalog-conflict:\(id)"
        )
        signals[identity.rawValue] = ResourceHealthSignal(
            identity: identity,
            level: .unhealthy,
            reason: reason
        )
    }

    for repository in catalog.repositories {
        for conflict in repository.serverConflicts {
            append(
                id: "server-endpoint:\(conflict.id)",
                origins: conflict.activeSourceIdentities.map { $0.origin },
                reason: conflict.message
            )
        }
        for conflict in repository.serverMembershipConflicts {
            append(
                id: "server-membership:\(conflict.id)",
                origins: conflict.activeSourceIdentities.map { $0.origin },
                reason: conflict.message
            )
        }
        for conflict in repository.dockerMembershipConflicts {
            append(
                id: "docker-membership:\(conflict.id)",
                origins: conflict.sourceIdentities.map { $0.origin },
                reason: conflict.message
            )
        }
    }
    return signals.values.sorted { $0.id < $1.id }
}

private func repositoryInventorySources(from inventory: Inventory) -> [RepositoryInventorySource] {
    let nestedOrigins = [inventory.origin]
        + inventory.servers.map(\.origin)
        + inventory.docker.containers.map(\.origin)
        + inventory.postgres.map(\.origin)
        + inventory.projectUsage.map(\.origin)
    var origins: [CoordinatorOrigin] = []
    var seen = Set<String>()
    for origin in nestedOrigins.compactMap({ $0 }) where seen.insert(origin.id).inserted {
        origins.append(origin)
    }
    let fallback = inventory.origin ?? CoordinatorOrigin(
        label: "Unattributed inventory",
        home: "/fixtures/unattributed-coordinator"
    )
    if origins.isEmpty {
        origins = [fallback]
    }

    func belongs(_ origin: CoordinatorOrigin?, to candidate: CoordinatorOrigin) -> Bool {
        (origin ?? fallback).id == candidate.id
    }

    return origins.map { origin in
        var slice = Inventory(
            coordinatorHome: origin.home,
            statePath: origin.statePath,
            project: inventory.project,
            urls: inventory.urls.filter { belongs($0.origin, to: origin) },
            servers: inventory.servers.filter { belongs($0.origin, to: origin) },
            leases: inventory.leases.filter { belongs($0.origin, to: origin) },
            recentEvents: inventory.recentEvents.filter { belongs($0.origin, to: origin) },
            docker: DockerSummary(
                available: inventory.docker.available,
                error: inventory.docker.error,
                statsError: inventory.docker.statsError,
                containers: inventory.docker.containers.filter { belongs($0.origin, to: origin) },
                postgres: inventory.docker.postgres.filter { belongs($0.origin, to: origin) }
            ),
            postgres: inventory.postgres.filter { belongs($0.origin, to: origin) },
            backups: inventory.backups.filter { belongs($0.origin, to: origin) },
            projectUsage: inventory.projectUsage.filter { belongs($0.origin, to: origin) }
        )
        slice.origin = origin
        return RepositoryInventorySource(origin: origin, inventory: slice)
    }
}

private func repositoryDockerNativeID(_ container: DockerContainer) -> String? {
    dockerImmutableID(container) ?? normalizedLabel(container.name)
}

/// Metrics freshness and mutation authority are separate. The catalog keeps
/// every raw observation and may choose a freshest sample for aggregation,
/// while `OpsStore.mergeInventories` has already resolved coordinator-sidecar
/// or Compose ownership for actions. Reuse that exact merged row for visible
/// identity so selection and mutation cannot drift to a different observer.
private func repositoryDockerPresentation(
    _ resource: RepositoryDockerResource,
    inventory: Inventory
) -> DockerContainer {
    let nativeID = repositoryDockerNativeID(resource.representative)
    let merged = (inventory.docker.containers + inventory.postgres).first { candidate in
        guard let nativeID else { return false }
        return repositoryDockerNativeID(candidate) == nativeID
    }
    var container = merged ?? resource.representative
    container.observationOrigins = resource.sourceOrigins.sorted { $0.id < $1.id }
    if let membershipError = resource.membershipError {
        container.origin = nil
        container.ownershipError = membershipError
    }
    if container.ownershipCandidates.isEmpty {
        if let origin = container.origin {
            container.ownershipCandidates = [origin]
        } else {
            container.ownershipCandidates = resource.sourceOrigins.sorted { $0.id < $1.id }
        }
    }
    return container
}

private struct MutableRepositorySourceObservation {
    let repository: RepositoryIdentity
    let origin: CoordinatorOrigin
    var displayLabels = Set<String>()
    var usageRows: [ProjectUsage] = []
    var serverIdentities = Set<ResourceIdentity>()
    var dockerIdentities = Set<ResourceIdentity>()

    func frozen() -> RepositorySourceObservation {
        RepositorySourceObservation(
            repository: repository,
            origin: origin,
            displayLabels: displayLabels.sorted(),
            usageRows: usageRows.sorted { $0.id < $1.id },
            serverIdentities: serverIdentities.sorted(),
            dockerIdentities: dockerIdentities.sorted()
        )
    }
}

private struct PendingRepositoryDockerObservation {
    let observation: RepositoryDockerObservation
    let membership: RepositoryMembershipResolution
}

private struct PendingRepositoryServerObservation {
    let observation: RepositoryServerObservation
    let membership: RepositoryMembershipResolution
}

/// A raw path claim remains evidence even when the path is missing or is not a
/// Git worktree. Only a verified repository can become an active project, but
/// unresolved claims still participate in ambiguity detection.
private struct RepositoryPathClaim: Hashable {
    let evidencePath: String
    let repository: RepositoryIdentity?

    init?(projectPath: String?) {
        guard let evidencePath = normalizedAbsoluteProjectPath(projectPath) else { return nil }
        self.evidencePath = evidencePath
        self.repository = RepositoryIdentity(projectPath: evidencePath)
    }

    var resolutionKey: String {
        repository?.id ?? "unverified:\(evidencePath)"
    }
}

private struct RepositoryMembershipResolution {
    let claims: [RepositoryPathClaim]

    init(_ claims: Set<RepositoryPathClaim>) {
        self.claims = claims.sorted {
            ($0.resolutionKey, $0.evidencePath) < ($1.resolutionKey, $1.evidencePath)
        }
    }

    var resolutionKeys: Set<String> { Set(claims.map(\.resolutionKey)) }
    var repositories: [RepositoryIdentity] {
        Set(claims.compactMap(\.repository)).sorted()
    }
    var claimedPaths: [String] { Set(claims.map(\.evidencePath)).sorted() }
    var isConflicting: Bool { resolutionKeys.count > 1 }
    var repository: RepositoryIdentity? {
        guard resolutionKeys.count == 1, repositories.count == 1 else { return nil }
        return repositories[0]
    }
}

private struct RepositoryCatalogBuilder {
    let sources: [RepositoryInventorySource]

    func build() -> RepositoryCatalog {
        var repositories = Set<RepositoryIdentity>()
        var sourceObservations: [String: MutableRepositorySourceObservation] = [:]
        var pendingServers: [PendingRepositoryServerObservation] = []
        var pendingDocker: [PendingRepositoryDockerObservation] = []
        var unassignedUsage: [ProjectUsage] = []

        for source in sources.sorted(by: { $0.origin.id < $1.origin.id }) {
            let origin = source.origin
            let servers = source.inventory.servers.map { normalizedServer($0, origin: origin) }
            let containers = primaryDockerContainers(in: source.inventory).map {
                normalizedContainer($0, origin: origin)
            }
            var serverMemberships: [String: Set<RepositoryPathClaim>] = [:]
            var dockerMemberships: [String: Set<RepositoryPathClaim>] = [:]

            for rawUsage in source.inventory.projectUsage {
                var usage = rawUsage
                usage.origin = origin
                let claim = RepositoryPathClaim(projectPath: usage.project)
                guard let repository = claim?.repository else {
                    unassignedUsage.append(usage)
                    if let claim {
                        for nativeID in usage.serverIDs ?? [] {
                            serverMemberships[nativeID, default: []].insert(claim)
                        }
                        for name in usage.containerNames ?? [] {
                            dockerMemberships[name, default: []].insert(claim)
                        }
                    }
                    continue
                }
                repositories.insert(repository)
                updateSourceObservation(
                    in: &sourceObservations,
                    repository: repository,
                    origin: origin,
                    labels: [usage.name, usage.projectKey].compactMap { normalizedLabel($0) },
                    usage: usage
                )
                for nativeID in usage.serverIDs ?? [] {
                    if let claim { serverMemberships[nativeID, default: []].insert(claim) }
                }
                for name in usage.containerNames ?? [] {
                    if let claim { dockerMemberships[name, default: []].insert(claim) }
                }
            }

            for server in servers {
                let sourceIdentity = server.resourceIdentity
                    ?? ResourceIdentity(origin: origin, kind: .server, nativeID: server.coordinatorID ?? server.id)
                var claims = serverMemberships[server.coordinatorID ?? server.id] ?? []
                if let explicit = RepositoryPathClaim(projectPath: server.project) {
                    claims.insert(explicit)
                }
                let observation = RepositoryServerObservation(sourceIdentity: sourceIdentity, server: server)
                pendingServers.append(
                    PendingRepositoryServerObservation(
                        observation: observation,
                        membership: RepositoryMembershipResolution(claims)
                    )
                )
            }

            for container in containers {
                guard let sourceIdentity = sourceDockerIdentity(container, origin: origin) else { continue }
                var claims = container.name.flatMap { dockerMemberships[$0] } ?? []
                if let explicit = RepositoryPathClaim(projectPath: container.project) {
                    claims.insert(explicit)
                }
                let observation = RepositoryDockerObservation(sourceIdentity: sourceIdentity, container: container)
                pendingDocker.append(
                    PendingRepositoryDockerObservation(
                        observation: observation,
                        membership: RepositoryMembershipResolution(claims)
                    )
                )
            }
        }

        var serverBuckets: [RepositoryIdentity: [RepositoryServerObservation]] = [:]
        var unassignedServers: [RepositoryServerObservation] = []
        var serverMembershipConflicts: [RepositoryIdentity: [RepositoryServerMembershipConflict]] = [:]
        // A damaged or partially migrated state file can repeat one native
        // server row. Reconcile its claims without letting duplicate keys trap
        // the Board process; presentation still collapses the observations to
        // one logical service below.
        var pendingServerClaimsByIdentity: [ResourceIdentity: Set<RepositoryPathClaim>] = [:]
        for pending in pendingServers {
            pendingServerClaimsByIdentity[pending.observation.sourceIdentity, default: []]
                .formUnion(pending.membership.claims)
        }
        var resolvedServerRepositories: [ResourceIdentity: RepositoryIdentity] = [:]
        var serverConflictByIdentity: [ResourceIdentity: RepositoryServerMembershipConflict] = [:]

        func retainServerConflict(
            observations: [RepositoryServerObservation],
            membership: RepositoryMembershipResolution
        ) {
            let sourceIdentities = observations.map(\.sourceIdentity).sorted()
            let conflict = RepositoryServerMembershipConflict(
                id: (sourceIdentities.map(\.rawValue) + membership.resolutionKeys.sorted())
                    .joined(separator: "||"),
                repositories: membership.repositories,
                activeSourceIdentities: sourceIdentities,
                claimedPaths: membership.claimedPaths
            )
            for identity in sourceIdentities { serverConflictByIdentity[identity] = conflict }
            for repository in membership.repositories {
                repositories.insert(repository)
                if serverMembershipConflicts[repository, default: []].contains(where: { $0.id == conflict.id }) == false {
                    serverMembershipConflicts[repository, default: []].append(conflict)
                }
            }
        }

        // Active observations can corroborate a pathless observer, but one
        // physical process/listener claimed by different repository paths is
        // removed from every candidate aggregate. This prevents both mutation
        // routing and Project Load metrics from counting it once per claimant.
        let activeServerObservations = pendingServers
            .map(\.observation)
            .filter { isActiveServerObservation($0.server) }
        for physicalGroup in physicalServerGroups(activeServerObservations) {
            let membership = RepositoryMembershipResolution(
                Set(physicalGroup.flatMap { pendingServerClaimsByIdentity[$0.sourceIdentity] ?? [] })
            )
            if membership.isConflicting {
                retainServerConflict(observations: physicalGroup, membership: membership)
            } else if let repository = membership.repository {
                for observation in physicalGroup {
                    resolvedServerRepositories[observation.sourceIdentity] = repository
                }
            }
        }

        // Stopped and otherwise non-active records cannot use endpoint
        // corroboration. Their own complete claim set must still fail closed.
        for pending in pendingServers where resolvedServerRepositories[pending.observation.sourceIdentity] == nil
            && serverConflictByIdentity[pending.observation.sourceIdentity] == nil {
            if pending.membership.isConflicting {
                retainServerConflict(observations: [pending.observation], membership: pending.membership)
            } else if let repository = pending.membership.repository {
                resolvedServerRepositories[pending.observation.sourceIdentity] = repository
            }
        }

        for pending in pendingServers {
            let identity = pending.observation.sourceIdentity
            if let conflict = serverConflictByIdentity[identity] {
                var server = pending.observation.server
                server.origin = nil
                server.ownershipError = conflict.message
                server.ownershipCandidates = Set(conflict.activeSourceIdentities.map { $0.origin })
                    .sorted { $0.id < $1.id }
                unassignedServers.append(
                    RepositoryServerObservation(sourceIdentity: identity, server: server)
                )
                continue
            }
            guard let repository = resolvedServerRepositories[identity] else {
                unassignedServers.append(pending.observation)
                continue
            }
            repositories.insert(repository)
            serverBuckets[repository, default: []].append(pending.observation)
            updateSourceObservation(
                in: &sourceObservations,
                repository: repository,
                origin: identity.origin,
                serverIdentity: identity
            )
        }

        var dockerBuckets: [RepositoryIdentity: [RepositoryDockerObservation]] = [:]
        var unassignedDocker: [RepositoryDockerResource] = []
        var dockerMembershipConflicts: [RepositoryIdentity: [RepositoryDockerMembershipConflict]] = [:]
        var resolvedDockerUsageKeys = Set<String>()
        let physicalDocker = Dictionary(grouping: pendingDocker) {
            dockerCatalogIdentity($0.observation)
        }
        for (identity, pending) in physicalDocker {
            let observations = pending.map(\.observation)
            let membership = RepositoryMembershipResolution(Set(pending.flatMap { $0.membership.claims }))
            let candidates = membership.repositories
            if !membership.isConflicting, let repository = membership.repository {
                repositories.insert(repository)
                dockerBuckets[repository, default: []].append(contentsOf: observations)
                for observation in observations {
                    if let name = normalizedLabel(observation.container.name) {
                        resolvedDockerUsageKeys.insert(
                            dockerUsageEvidenceKey(
                                origin: observation.sourceIdentity.origin,
                                containerName: name
                            )
                        )
                    }
                    updateSourceObservation(
                        in: &sourceObservations,
                        repository: repository,
                        origin: observation.sourceIdentity.origin,
                        dockerIdentity: observation.sourceIdentity
                    )
                }
            } else {
                let membershipConflict = membership.isConflicting
                    ? RepositoryDockerMembershipConflict(
                        resource: identity,
                        repositories: candidates,
                        sourceIdentities: observations.map(\.sourceIdentity).sorted(),
                        claimedPaths: membership.claimedPaths
                    )
                    : nil
                if let membershipConflict {
                    for repository in candidates {
                        repositories.insert(repository)
                        dockerMembershipConflicts[repository, default: []].append(membershipConflict)
                    }
                }
                unassignedDocker.append(
                    buildDockerResource(
                        identity: identity,
                        observations: observations,
                        repositoryCandidates: candidates,
                        membershipError: membershipConflict?.message
                    )
                )
            }
        }

        unassignedUsage = unresolvedUsageEvidence(
            unassignedUsage,
            excluding: resolvedDockerUsageKeys
        )

        let aggregates = repositories.sorted().map { repository in
            let servers = buildManagedServers(
                repository: repository,
                observations: serverBuckets[repository] ?? [],
                membershipConflicts: serverMembershipConflicts[repository] ?? []
            )
            let docker = buildDockerResources(
                observations: dockerBuckets[repository] ?? [],
                repositoryCandidates: [repository]
            )
            let observations = sourceObservations.values
                .filter { $0.repository == repository }
                .map { $0.frozen() }
                .sorted { $0.origin.id < $1.origin.id }
            return RepositoryAggregate(
                identity: repository,
                observedLabels: Set(observations.flatMap(\.displayLabels)).sorted(),
                sourceObservations: observations,
                servers: servers,
                docker: docker,
                usage: aggregateUsage(servers: servers, docker: docker),
                controlOrigin: conservativeControlOrigin(servers: servers, docker: docker),
                serverMembershipConflicts: serverMembershipConflicts[repository] ?? [],
                dockerMembershipConflicts: dockerMembershipConflicts[repository] ?? []
            )
        }

        return RepositoryCatalog(
            repositories: aggregates,
            unassigned: UnassignedResources(
                servers: unassignedServers.sorted { $0.sourceIdentity < $1.sourceIdentity },
                docker: unassignedDocker.sorted { $0.identity < $1.identity },
                usageObservations: unassignedUsage.sorted { $0.id < $1.id }
            )
        )
    }
}

private func normalizedServer(_ raw: ManagedServer, origin: CoordinatorOrigin) -> ManagedServer {
    var server = raw
    let nativeID = server.coordinatorID ?? server.id
    server.coordinatorID = nativeID
    server.origin = origin
    server.id = ResourceIdentity(origin: origin, kind: .server, nativeID: nativeID).rawValue
    return server
}

private func normalizedContainer(_ raw: DockerContainer, origin: CoordinatorOrigin) -> DockerContainer {
    var container = raw
    container.origin = origin
    return container
}

private func primaryDockerContainers(in inventory: Inventory) -> [DockerContainer] {
    var result = inventory.docker.containers
    var seen = Set(result.compactMap(dockerImmutableID))
    for database in inventory.postgres {
        if let immutableID = dockerImmutableID(database), seen.insert(immutableID).inserted {
            result.append(database)
        }
    }
    return result
}

private func normalizedLabel(_ value: String?) -> String? {
    guard let value else { return nil }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
}

private func dockerUsageEvidenceKey(origin: CoordinatorOrigin, containerName: String) -> String {
    "\(origin.id)|\(containerName)"
}

private func unresolvedUsageEvidence(
    _ rows: [ProjectUsage],
    excluding resolvedDockerUsageKeys: Set<String>
) -> [ProjectUsage] {
    rows.compactMap { row in
        guard let origin = row.origin else { return row }
        let names = row.containerNames ?? []
        guard !names.isEmpty else { return row }
        let unresolved = names.filter {
            !resolvedDockerUsageKeys.contains(
                dockerUsageEvidenceKey(origin: origin, containerName: $0)
            )
        }
        guard !unresolved.isEmpty else { return nil }
        var row = row
        row.containerNames = unresolved
        row.containerCount = unresolved.count
        return row
    }
}

private func sourceObservationKey(repository: RepositoryIdentity, origin: CoordinatorOrigin) -> String {
    "\(repository.id)|source|\(origin.id)"
}

private func updateSourceObservation(
    in values: inout [String: MutableRepositorySourceObservation],
    repository: RepositoryIdentity,
    origin: CoordinatorOrigin,
    labels: [String] = [],
    usage: ProjectUsage? = nil,
    serverIdentity: ResourceIdentity? = nil,
    dockerIdentity: ResourceIdentity? = nil
) {
    let key = sourceObservationKey(repository: repository, origin: origin)
    var value = values[key] ?? MutableRepositorySourceObservation(repository: repository, origin: origin)
    value.displayLabels.formUnion(labels)
    if let usage { value.usageRows.append(usage) }
    if let serverIdentity { value.serverIdentities.insert(serverIdentity) }
    if let dockerIdentity { value.dockerIdentities.insert(dockerIdentity) }
    values[key] = value
}

private func buildManagedServers(
    repository: RepositoryIdentity,
    observations: [RepositoryServerObservation],
    membershipConflicts: [RepositoryServerMembershipConflict]
) -> [RepositoryManagedServer] {
    let buckets = Dictionary(grouping: observations) {
        RepositoryLogicalServerIdentity(repository: repository, serviceName: $0.server.name)
    }
    return buckets.map { identity, bucket in
        let sorted = bucket.sorted { $0.sourceIdentity < $1.sourceIdentity }
        let active = sorted.filter { isActiveServerObservation($0.server) }
        let physicalGroups = physicalServerGroups(active)
        let conflict = physicalGroups.count > 1
            ? RepositoryServerConflict(
                service: identity,
                activeSourceIdentities: active.map(\.sourceIdentity).sorted()
            )
            : nil
        let membershipConflicts = membershipConflicts.filter { membershipConflict in
            !Set(membershipConflict.activeSourceIdentities).isDisjoint(with: sorted.map(\.sourceIdentity))
        }
        let representative = sorted.max(by: { serverObservationRank($0) < serverObservationRank($1) })!.server
        let controlCandidates = possibleServerControlOrigins(
            observations: sorted,
            active: active,
            conflict: conflict,
            membershipConflicts: membershipConflicts
        )
        let actionOrigin = controlCandidates.count == 1 ? controlCandidates[0] : nil
        return RepositoryManagedServer(
            identity: identity,
            representative: representative,
            observations: sorted,
            conflict: conflict,
            membershipConflicts: membershipConflicts,
            controlCandidates: controlCandidates,
            actionOrigin: actionOrigin
        )
    }
    .sorted { $0.identity < $1.identity }
}

private func possibleServerControlOrigins(
    observations: [RepositoryServerObservation],
    active: [RepositoryServerObservation],
    conflict: RepositoryServerConflict?,
    membershipConflicts: [RepositoryServerMembershipConflict]
) -> [CoordinatorOrigin] {
    guard conflict == nil, membershipConflicts.isEmpty else { return [] }

    // One active source is the only current controller even when other homes
    // retain stale stopped definitions. Multiple active source records remain
    // ambiguous even when they happen to observe the same PID/listener: each
    // coordinator would update a different lease and lifecycle journal.
    let activeOrigins = Set(active.map { $0.sourceIdentity.origin })
    if activeOrigins.count == 1 { return activeOrigins.sorted { $0.id < $1.id } }
    if activeOrigins.count > 1 { return [] }

    // With every observation stopped, only a single source namespace is a
    // proven restart target. Never pick an arbitrary legacy home.
    let allOrigins = Set(observations.map { $0.sourceIdentity.origin })
    return allOrigins.sorted { $0.id < $1.id }
}

private func isActiveServerObservation(_ server: ManagedServer) -> Bool {
    if isStoppedStatus(server.status) { return false }
    if server.health?.pidAlive == true || server.health?.ok == true { return true }
    let status = (server.status ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return status == "running"
        || status == "starting"
        || status == "unhealthy"
        || status == "degraded"
        || status == "orphaned"
        || status.hasPrefix("up")
}

private func samePhysicalServer(_ lhs: RepositoryServerObservation, _ rhs: RepositoryServerObservation) -> Bool {
    if let leftPID = lhs.server.pid, let rightPID = rhs.server.pid, leftPID == rightPID {
        return true
    }
    if let leftPort = lhs.server.port, let rightPort = rhs.server.port, leftPort == rightPort {
        let leftHost = normalizedServerHost(lhs.server.host)
        let rightHost = normalizedServerHost(rhs.server.host)
        if leftHost == rightHost { return true }
    }
    if let leftURL = normalizedLabel(lhs.server.currentURL),
       let rightURL = normalizedLabel(rhs.server.currentURL),
       leftURL == rightURL {
        return true
    }
    return false
}

private func normalizedServerHost(_ value: String?) -> String {
    let host = (value ?? "127.0.0.1").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return host == "localhost" ? "127.0.0.1" : host
}

private func physicalServerGroups(
    _ observations: [RepositoryServerObservation]
) -> [[RepositoryServerObservation]] {
    var groups: [[RepositoryServerObservation]] = []
    for observation in observations {
        let matching = groups.indices.filter { index in
            groups[index].contains { samePhysicalServer($0, observation) }
        }
        guard let first = matching.first else {
            groups.append([observation])
            continue
        }
        groups[first].append(observation)
        for index in matching.dropFirst().reversed() {
            groups[first].append(contentsOf: groups.remove(at: index))
        }
    }
    return groups
}

private func serverObservationRank(_ observation: RepositoryServerObservation) -> (Int, Int, String, String) {
    let server = observation.server
    return (
        isActiveServerObservation(server) ? 1 : 0,
        server.health?.ok == true ? 1 : 0,
        server.updatedAt ?? server.stoppedAt ?? server.createdAt ?? "",
        observation.sourceIdentity.rawValue
    )
}

private func dockerImmutableID(_ container: DockerContainer) -> String? {
    // The inventory's primary container id is present even when a particular
    // source could not collect stats; prefer it so that a stats-degraded copy
    // still reconciles with observations from healthy sources.
    for value in [container.id, container.stats?.containerID] {
        if let value = normalizedLabel(value) { return value }
    }
    return nil
}

private func sourceDockerIdentity(
    _ container: DockerContainer,
    origin: CoordinatorOrigin
) -> ResourceIdentity? {
    let nativeID = dockerImmutableID(container) ?? normalizedLabel(container.name)
    guard let nativeID else { return nil }
    return ResourceIdentity(
        origin: origin,
        kind: container.isPostgresLike ? .database : .docker,
        nativeID: nativeID
    )
}

private func dockerCatalogIdentity(_ observation: RepositoryDockerObservation) -> RepositoryDockerIdentity {
    if let immutableID = dockerImmutableID(observation.container) {
        return RepositoryDockerIdentity(rawValue: "container:\(immutableID)", isImmutable: true)
    }
    return RepositoryDockerIdentity(
        rawValue: "observation:\(observation.sourceIdentity.rawValue)",
        isImmutable: false
    )
}

private func buildDockerResources(
    observations: [RepositoryDockerObservation],
    repositoryCandidates: [RepositoryIdentity] = []
) -> [RepositoryDockerResource] {
    Dictionary(grouping: observations, by: dockerCatalogIdentity).map { identity, bucket in
        buildDockerResource(
            identity: identity,
            observations: bucket,
            repositoryCandidates: repositoryCandidates,
            membershipError: nil
        )
    }
    .sorted { $0.identity < $1.identity }
}

private func buildDockerResource(
    identity: RepositoryDockerIdentity,
    observations: [RepositoryDockerObservation],
    repositoryCandidates: [RepositoryIdentity],
    membershipError: String?
) -> RepositoryDockerResource {
    let sorted = observations.sorted { $0.sourceIdentity < $1.sourceIdentity }
    let representative = sorted.max(by: { dockerObservationRank($0) < dockerObservationRank($1) })!.container
    return RepositoryDockerResource(
        identity: identity,
        representative: representative,
        observations: sorted,
        repositoryCandidates: repositoryCandidates,
        membershipError: membershipError,
        controlCandidates: dockerControlCandidates(
            observations: sorted,
            repositoryCandidates: repositoryCandidates,
            membershipError: membershipError
        )
    )
}

private func dockerControlCandidates(
    observations: [RepositoryDockerObservation],
    repositoryCandidates: [RepositoryIdentity],
    membershipError: String?
) -> [CoordinatorOrigin] {
    guard repositoryCandidates.count == 1, membershipError == nil else { return [] }
    let sidecarOrigins = Set(observations.compactMap { observation -> CoordinatorOrigin? in
        observation.container.metadataSource == "coordinator_sidecar"
            ? observation.sourceIdentity.origin
            : nil
    })
    if !sidecarOrigins.isEmpty {
        return sidecarOrigins.sorted { $0.id < $1.id }
    }
    return Set(observations.map { $0.sourceIdentity.origin }).sorted { $0.id < $1.id }
}

private func dockerObservationRank(_ observation: RepositoryDockerObservation) -> (Double, Int, Int, String) {
    let container = observation.container
    let metadataRank = container.project?.isEmpty == false ? 1 : 0
    return (
        container.stats?.timestampTs ?? 0,
        container.isRunning ? 1 : 0,
        metadataRank,
        observation.sourceIdentity.rawValue
    )
}

private func conservativeControlOrigin(
    servers: [RepositoryManagedServer],
    docker: [RepositoryDockerResource]
) -> CoordinatorOrigin? {
    // A whole-project command is routed only through a source that can prove
    // coverage for every logical server and every Docker sidecar/Compose
    // resource. Display aggregation stays independent from this binding.
    let constraints = servers.map(\.controlCandidates) + docker.map(\.controlCandidates)
    guard !constraints.isEmpty, constraints.allSatisfy({ !$0.isEmpty }) else { return nil }
    var candidates = Set(constraints[0])
    for constraint in constraints.dropFirst() {
        candidates.formIntersection(constraint)
    }
    guard candidates.count == 1 else { return nil }
    return candidates.first
}

private func aggregateUsage(
    servers: [RepositoryManagedServer],
    docker: [RepositoryDockerResource]
) -> RepositoryUsage {
    var processesByPID: [Int: ProcessUsage] = [:]
    var fallbackProcessCount = 0
    var fallbackCPU = 0.0
    var fallbackMemory = 0.0

    for server in servers {
        var foundConcreteProcess = false
        for observation in server.observations {
            guard let usage = observation.server.processUsage else { continue }
            let processes = concreteProcesses(in: usage)
            if !processes.isEmpty { foundConcreteProcess = true }
            for process in processes {
                guard let pid = process.pid else { continue }
                if let current = processesByPID[pid] {
                    if processObservationRank(process) > processObservationRank(current) {
                        processesByPID[pid] = process
                    }
                } else {
                    processesByPID[pid] = process
                }
            }
        }
        if !foundConcreteProcess, let usage = server.representative.processUsage {
            fallbackProcessCount += usage.processCount ?? usage.pids?.count ?? 0
            fallbackCPU += usage.cpuPercent ?? 0
            fallbackMemory += usage.rssBytes ?? usage.memoryBytes ?? 0
        }
    }

    let processes = processesByPID.values.sorted {
        ($0.cpuPercent ?? 0, $0.rssBytes ?? $0.memoryBytes ?? 0, $0.pid ?? 0)
            > ($1.cpuPercent ?? 0, $1.rssBytes ?? $1.memoryBytes ?? 0, $1.pid ?? 0)
    }
    var cpu = fallbackCPU + processes.reduce(0) { $0 + ($1.cpuPercent ?? 0) }
    var memory = fallbackMemory + processes.reduce(0) { $0 + ($1.rssBytes ?? $1.memoryBytes ?? 0) }

    for resource in docker {
        guard let stats = resource.representative.stats, stats.live != false else { continue }
        cpu += stats.cpuPercent ?? 0
        memory += stats.memoryUsageBytes ?? 0
    }

    return RepositoryUsage(
        serverCount: servers.count,
        containerCount: docker.count,
        processCount: processes.count + fallbackProcessCount,
        cpuPercent: cpu,
        memoryBytes: memory,
        hotProcesses: Array(processes.prefix(5))
    )
}

private func concreteProcesses(in usage: ProcessUsage) -> [ProcessUsage] {
    if let children = usage.processes, !children.isEmpty {
        return children.flatMap(concreteProcesses)
    }
    return usage.pid == nil ? [] : [usage]
}

private func processObservationRank(_ process: ProcessUsage) -> (String, Int) {
    let completeness = (process.cpuPercent == nil ? 0 : 1) + (process.rssBytes == nil && process.memoryBytes == nil ? 0 : 1)
    return (process.sampledAt ?? "", completeness)
}
