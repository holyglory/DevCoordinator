import Foundation

enum RepositoryProjectKind: String, Decodable, Equatable, Sendable {
    case root
    case temporary
}

struct RepositoryTreeMetricTotal: Decodable, Equatable, Sendable {
    let resourceCount: Int?
    let cpuPercent: Double?
    let memoryBytes: Double?
    let processCount: Int?

    enum CodingKeys: String, CodingKey {
        case resourceCount = "resource_count"
        case cpuPercent = "cpu_percent"
        case memoryBytes = "memory_bytes"
        case processCount = "process_count"
    }
}

/// Coordinator-owned usage for either a repository family or one project
/// scope. Resource-kind breakdowns may evolve independently; the Board needs
/// only the stable totals used by its compact Project Load presentation.
struct RepositoryTreeUsage: Decodable, Equatable, Sendable {
    let cpuPercent: Double?
    let memoryBytes: Double?
    let processCount: Int?
    let total: RepositoryTreeMetricTotal?
    let server: RepositoryTreeMetricTotal?
    let docker: RepositoryTreeMetricTotal?

    enum CodingKeys: String, CodingKey {
        case cpuPercent = "cpu_percent"
        case memoryBytes = "memory_bytes"
        case processCount = "process_count"
        case total, server, docker
    }

    var effectiveCPUPercent: Double? { total?.cpuPercent ?? cpuPercent }
    var effectiveMemoryBytes: Double? { total?.memoryBytes ?? memoryBytes }
    var effectiveProcessCount: Int? { total?.processCount ?? processCount }
}

struct NormalizedRepositoryTreeRoot: Decodable, Equatable, Sendable {
    let repoID: String
    let canonicalRoot: String
    let displayName: String

    enum CodingKeys: String, CodingKey {
        case repoID = "repo_id"
        case canonicalRoot = "canonical_root"
        case displayName = "display_name"
    }
}

struct NormalizedRepositoryTreeScope: Decodable, Equatable, Sendable {
    let repoID: String
    let kind: RepositoryProjectKind
    let canonicalRoot: String
    let displayName: String
    let runID: String?
    let expiresAt: String?
    let killAfterRun: Bool?
    let usage: RepositoryTreeUsage?
    let serverIDs: [String]
    let containerResourceIDs: [String]
    let databaseBindingIDs: [String]

    enum CodingKeys: String, CodingKey {
        case repoID = "repo_id"
        case kind
        case canonicalRoot = "canonical_root"
        case displayName = "display_name"
        case runID = "run_id"
        case expiresAt = "expires_at"
        case killAfterRun = "kill_after_run"
        case usage
        case serverIDs = "server_ids"
        case containerResourceIDs = "container_resource_ids"
        case databaseBindingIDs = "database_binding_ids"
    }
}

struct NormalizedRepositoryTree: Decodable, Equatable, Sendable {
    let familyID: String
    let rootRepository: NormalizedRepositoryTreeRoot
    let usage: RepositoryTreeUsage?
    let scopes: [NormalizedRepositoryTreeScope]

    enum CodingKeys: String, CodingKey {
        case familyID = "family_id"
        case rootRepository = "root_repository"
        case usage, scopes
    }
}

struct RepositoryExecutionContext: Hashable, Sendable {
    let familyID: String
    let rootRepositoryID: String
    let rootCanonicalRoot: String
    let effectiveRepositoryID: String
    let effectiveCanonicalRoot: String
    let projectKind: RepositoryProjectKind
    let runID: String?
    let expiresAt: String?
    let killAfterRun: Bool?
}

struct RepositoryScopePresentation: Identifiable, Equatable {
    let definition: NormalizedRepositoryTreeScope
    let group: ProjectGroup
    let context: RepositoryExecutionContext

    var id: String { definition.repoID }
    var kind: RepositoryProjectKind { definition.kind }
    var displayName: String { definition.displayName }

    func breadcrumb(rootName: String) -> String {
        kind == .root ? rootName : "\(rootName) › \(displayName)"
    }

    var usage: ProjectUsage? {
        guard let authoritative = definition.usage else { return group.usage }
        var row = ProjectUsage(
            usageKey: "repo:\(definition.repoID)",
            project: definition.canonicalRoot,
            projectKey: definition.repoID,
            name: definition.displayName,
            serverIDs: definition.serverIDs,
            containerNames: (group.containers + group.databases).compactMap(\.name),
            serverCount: authoritative.server?.resourceCount ?? definition.serverIDs.count,
            containerCount: authoritative.docker?.resourceCount ?? definition.containerResourceIDs.count,
            processCount: authoritative.effectiveProcessCount,
            cpuPercent: authoritative.effectiveCPUPercent,
            memoryBytes: authoritative.effectiveMemoryBytes,
            processCPUPercent: authoritative.server?.cpuPercent,
            processMemoryBytes: authoritative.server?.memoryBytes,
            dockerCPUPercent: authoritative.docker?.cpuPercent,
            dockerMemoryBytes: authoritative.docker?.memoryBytes,
            processes: nil,
            hotProcesses: group.usage?.hotProcesses
        )
        row.origin = group.usage?.origin
        return row
    }
}

struct RepositoryTreePresentation: Identifiable, Equatable {
    let definition: NormalizedRepositoryTree
    let familyID: String
    let root: RepositoryScopePresentation
    let temporaryScopes: [RepositoryScopePresentation]

    var id: String { familyID }
    var scopes: [RepositoryScopePresentation] { [root] + temporaryScopes }
    var resourceCount: Int {
        scopes.reduce(0) {
            $0 + $1.group.servers.count + $1.group.containers.count + $1.group.databases.count
        }
    }

    var status: String {
        let statuses = scopes.map { projectGroupStatus($0.group) }
        if statuses.contains("unhealthy") { return "unhealthy" }
        if statuses.contains("running") { return "running" }
        return "stopped"
    }

    var usage: ProjectUsage? {
        guard let authoritative = definition.usage else { return root.group.usage }
        let groups = scopes.map(\.group)
        let scopeDefinitions = scopes.map(\.definition)
        var row = ProjectUsage(
            usageKey: "family:\(familyID)",
            project: root.definition.canonicalRoot,
            projectKey: familyID,
            name: root.definition.displayName,
            serverIDs: scopeDefinitions.flatMap(\.serverIDs),
            containerNames: groups.flatMap { $0.containers + $0.databases }.compactMap(\.name),
            serverCount: authoritative.server?.resourceCount
                ?? scopeDefinitions.flatMap(\.serverIDs).count,
            containerCount: authoritative.docker?.resourceCount
                ?? scopeDefinitions.flatMap(\.containerResourceIDs).count,
            processCount: authoritative.effectiveProcessCount,
            cpuPercent: authoritative.effectiveCPUPercent,
            memoryBytes: authoritative.effectiveMemoryBytes,
            processCPUPercent: authoritative.server?.cpuPercent,
            processMemoryBytes: authoritative.server?.memoryBytes,
            dockerCPUPercent: authoritative.docker?.cpuPercent,
            dockerMemoryBytes: authoritative.docker?.memoryBytes,
            processes: nil,
            hotProcesses: groups.compactMap(\.usage).flatMap { $0.hotProcesses ?? [] }
        )
        row.origin = root.group.usage?.origin
        return row
    }

    func breadcrumb(forRepositoryID repositoryID: String?) -> String? {
        guard let repositoryID,
              let scope = scopes.first(where: { $0.definition.repoID == repositoryID })
        else { return nil }
        return scope.breadcrumb(rootName: root.displayName)
    }
}

func makeRepositoryTreePresentations(
    groups: [ProjectGroup],
    definitions: [NormalizedRepositoryTree]
) -> [RepositoryTreePresentation] {
    let repositoryGroups = groups.filter(\.isRepository)
    let groupsByRepositoryID = Dictionary(
        uniqueKeysWithValues: repositoryGroups.compactMap { group in
            group.repositoryID.map { ($0, group) }
        }
    )
    return definitions.compactMap { tree in
        let scopes = tree.scopes.compactMap { scope -> RepositoryScopePresentation? in
            guard let group = groupsByRepositoryID[scope.repoID] else { return nil }
            return RepositoryScopePresentation(
                definition: scope,
                group: group,
                context: RepositoryExecutionContext(
                    familyID: tree.familyID,
                    rootRepositoryID: tree.rootRepository.repoID,
                    rootCanonicalRoot: tree.rootRepository.canonicalRoot,
                    effectiveRepositoryID: scope.repoID,
                    effectiveCanonicalRoot: scope.canonicalRoot,
                    projectKind: scope.kind,
                    runID: scope.runID,
                    expiresAt: scope.expiresAt,
                    killAfterRun: scope.killAfterRun
                )
            )
        }
        guard let root = scopes.first(where: { $0.kind == .root }) else { return nil }
        return RepositoryTreePresentation(
            definition: tree,
            familyID: tree.familyID,
            root: root,
            temporaryScopes: scopes.filter { $0.kind == .temporary }
        )
    }
}
