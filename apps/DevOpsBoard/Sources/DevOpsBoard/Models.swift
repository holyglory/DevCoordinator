import Foundation
import CryptoKit
import Darwin

struct Inventory: Decodable, Equatable, Sendable {
    var origin: CoordinatorOrigin? = nil
    var coordinatorHome: String?
    var statePath: String?
    var project: String?
    var urls: [ManagedURL]
    var servers: [ManagedServer]
    var leases: [PortLease]
    var recentEvents: [RecentEvent]
    var docker: DockerSummary
    var postgres: [DockerContainer]
    var backups: [DatabaseBackup]
    var projectUsage: [ProjectUsage]

    enum CodingKeys: String, CodingKey {
        case coordinatorHome = "coordinator_home"
        case statePath = "state_path"
        case project
        case urls
        case servers
        case leases
        case recentEvents = "recent_events"
        case docker
        case postgres
        case backups
        case projectUsage = "project_usage"
    }

    static let empty = Inventory(
        coordinatorHome: nil,
        statePath: nil,
        project: nil,
        urls: [],
        servers: [],
        leases: [],
        recentEvents: [],
        docker: DockerSummary(available: nil, error: nil, statsError: nil, containers: [], postgres: []),
        postgres: [],
        backups: [],
        projectUsage: []
    )
}

struct ManagedURL: Decodable, Identifiable, Hashable, Sendable {
    var id: String { "\(origin?.id ?? "unknown"):\(project ?? ""):\(name ?? ""):\(url ?? "")" }
    var origin: CoordinatorOrigin? = nil
    var name: String?
    var project: String?
    var url: String?
    var healthURL: String?
    var status: String?

    enum CodingKeys: String, CodingKey {
        case name, project, url, status
        case healthURL = "health_url"
    }
}

struct ManagedServer: Decodable, Identifiable, Hashable, Sendable {
    var id: String
    var coordinatorID: String? = nil
    var origin: CoordinatorOrigin? = nil
    var name: String
    var agent: String?
    var project: String?
    var cwd: String?
    var command: String?
    var commandTemplate: String?
    var port: Int?
    var host: String?
    var url: String?
    var healthURL: String?
    var leaseID: String?
    var pid: Int?
    var logPath: String?
    var status: String?
    var health: Health?
    var stoppedAt: String?
    var stoppedReason: String?
    var adopted: Bool?
    var missingCommand: Bool?
    var metadataSource: String?
    var updatedAt: String?
    var createdAt: String?
    var createdTs: Double?
    var duplicateCount: Int?
    var duplicateServerIDs: [String]?
    var urlIsCurrent: Bool?
    var portReused: Bool?
    var portReusedBy: PortReuseOwner?
    var processUsage: ProcessUsage?
    // Populated by the Board's repository catalog after source inventories
    // are reconciled. These are presentation/control facts, not coordinator
    // payload fields, so they deliberately have no CodingKeys.
    var ownershipError: String? = nil
    var ownershipCandidates: [CoordinatorOrigin] = []
    var observationOrigins: [CoordinatorOrigin] = []

    enum CodingKeys: String, CodingKey {
        case id, name, agent, project, cwd, port, host, url, pid, status, health
        case adopted
        case command = "cmd"
        case commandTemplate = "cmd_template"
        case healthURL = "health_url"
        case leaseID = "lease_id"
        case logPath = "log_path"
        case stoppedAt = "stopped_at"
        case stoppedReason = "stopped_reason"
        case missingCommand = "missing_command"
        case metadataSource = "metadata_source"
        case updatedAt = "updated_at"
        case createdAt = "created_at"
        case createdTs = "created_ts"
        case duplicateCount = "duplicate_count"
        case duplicateServerIDs = "duplicate_server_ids"
        case urlIsCurrent = "url_is_current"
        case portReused = "port_reused"
        case portReusedBy = "port_reused_by"
        case processUsage = "process_usage"
    }
}

struct ProcessUsage: Decodable, Hashable, Identifiable, Sendable {
    var id: String {
        if let pid { return "pid-\(pid)" }
        if let rootPIDs, !rootPIDs.isEmpty {
            return "roots-\(rootPIDs.map(String.init).joined(separator: "-"))"
        }
        return command ?? source ?? "process"
    }
    var source: String?
    var pid: Int?
    var ppid: Int?
    var rootPIDs: [Int]?
    var pids: [Int]?
    var processCount: Int?
    var cpuPercent: Double?
    var rssBytes: Double?
    var memoryBytes: Double?
    var command: String?
    var sampledAt: String?
    var project: String?
    var serverID: String?
    var serverName: String?
    var processes: [ProcessUsage]?
    var hotProcesses: [ProcessUsage]?
    var origin: CoordinatorOrigin? = nil

    enum CodingKeys: String, CodingKey {
        case source, pid, ppid, pids, command, project, processes
        case rootPIDs = "root_pids"
        case processCount = "process_count"
        case cpuPercent = "cpu_percent"
        case rssBytes = "rss_bytes"
        case memoryBytes = "memory_bytes"
        case sampledAt = "sampled_at"
        case serverID = "server_id"
        case serverName = "server_name"
        case hotProcesses = "hot_processes"
    }
}

struct ProjectUsage: Decodable, Hashable, Identifiable, Sendable {
    var id: String { "\(origin?.id ?? "unknown"):\(usageKey ?? project ?? projectKey ?? name ?? "project")" }
    var origin: CoordinatorOrigin? = nil
    var usageKey: String? = nil
    var project: String?
    var projectKey: String?
    var name: String?
    // Authoritative membership from the coordinator: the servers/containers a
    // row claims are exactly the ones whole-project actions act on.
    var serverIDs: [String]? = nil
    var containerNames: [String]? = nil
    var serverCount: Int?
    var containerCount: Int?
    var processCount: Int?
    var cpuPercent: Double?
    var memoryBytes: Double?
    var processCPUPercent: Double?
    var processMemoryBytes: Double?
    var dockerCPUPercent: Double?
    var dockerMemoryBytes: Double?
    var processes: [ProcessUsage]?
    var hotProcesses: [ProcessUsage]?

    enum CodingKeys: String, CodingKey {
        case project, name, processes
        case usageKey = "usage_key"
        case projectKey = "project_key"
        case serverIDs = "server_ids"
        case containerNames = "container_names"
        case serverCount = "server_count"
        case containerCount = "container_count"
        case processCount = "process_count"
        case cpuPercent = "cpu_percent"
        case memoryBytes = "memory_bytes"
        case processCPUPercent = "process_cpu_percent"
        case processMemoryBytes = "process_memory_bytes"
        case dockerCPUPercent = "docker_cpu_percent"
        case dockerMemoryBytes = "docker_memory_bytes"
        case hotProcesses = "hot_processes"
    }
}

struct PortReuseOwner: Decodable, Hashable, Sendable {
    var type: String?
    var id: String?
    var name: String?
    var project: String?
    var pid: Int?
    var cwd: String?
    var url: String?
}

struct Health: Decodable, Hashable, Sendable {
    var ok: Bool?
    var pidAlive: Bool?

    enum CodingKeys: String, CodingKey {
        case ok
        case pidAlive = "pid_alive"
    }
}

struct PortLease: Decodable, Identifiable, Hashable, Sendable {
    var id: String
    var coordinatorID: String? = nil
    var origin: CoordinatorOrigin? = nil
    var port: Int
    var agent: String?
    var project: String?
    var purpose: String?
    var status: String?
    var expiresAtISO: String?
    var serverID: String?
    var pendingOperationID: String?

    enum CodingKeys: String, CodingKey {
        case id, port, agent, project, purpose, status
        case expiresAtISO = "expires_at_iso"
        case serverID = "server_id"
        case pendingOperationID = "pending_operation_id"
    }
}

struct DockerSummary: Decodable, Hashable, Sendable {
    var available: Bool?
    var error: String?
    var statsError: String?
    var containers: [DockerContainer]
    var postgres: [DockerContainer]

    enum CodingKeys: String, CodingKey {
        case available, error, containers, postgres
        case statsError = "stats_error"
    }
}

struct DockerContainer: Decodable, Identifiable, Hashable, Sendable {
    var origin: CoordinatorOrigin? = nil
    var id: String?
    var name: String?
    var image: String?
    var status: String?
    var ports: String?
    var project: String?
    var agent: String?
    var role: String?
    var metadataSource: String?
    var adopted: Bool?
    var stats: DockerStats?
    var statsHistory: [DockerStats]?
    var database: String? = nil
    var databaseSizeBytes: Int64? = nil
    var databaseDiscoveryError: String? = nil
    var startedAt: String? = nil
    var ownershipError: String? = nil
    var ownershipCandidates: [CoordinatorOrigin] = []
    var observationOrigins: [CoordinatorOrigin] = []

    enum CodingKeys: String, CodingKey {
        case id, name, image, status, ports, project, agent, role, adopted, stats
        case metadataSource = "metadata_source"
        case statsHistory = "stats_history"
    }
}

struct DockerStats: Decodable, Identifiable, Hashable, Sendable {
    var id: String { "\(containerID ?? name ?? "container"):\(timestampTs ?? 0)" }
    var containerShortID: String?
    var containerID: String?
    var name: String?
    var timestamp: String?
    var timestampTs: Double?
    var live: Bool?
    var cpuPercent: Double?
    var memoryPercent: Double?
    var memoryUsageBytes: Double?
    var memoryLimitBytes: Double?
    var networkRxBytes: Double?
    var networkTxBytes: Double?
    var blockReadBytes: Double?
    var blockWriteBytes: Double?
    var networkRxRateBytesPerSecond: Double?
    var networkTxRateBytesPerSecond: Double?
    var blockReadRateBytesPerSecond: Double?
    var blockWriteRateBytesPerSecond: Double?
    var pids: Int?

    enum CodingKeys: String, CodingKey {
        case name, timestamp, live, pids
        case containerShortID = "id"
        case containerID = "container_id"
        case timestampTs = "timestamp_ts"
        case cpuPercent = "cpu_percent"
        case memoryPercent = "memory_percent"
        case memoryUsageBytes = "memory_usage_bytes"
        case memoryLimitBytes = "memory_limit_bytes"
        case networkRxBytes = "network_rx_bytes"
        case networkTxBytes = "network_tx_bytes"
        case blockReadBytes = "block_read_bytes"
        case blockWriteBytes = "block_write_bytes"
        case networkRxRateBytesPerSecond = "network_rx_rate_bytes_per_second"
        case networkTxRateBytesPerSecond = "network_tx_rate_bytes_per_second"
        case blockReadRateBytesPerSecond = "block_read_rate_bytes_per_second"
        case blockWriteRateBytesPerSecond = "block_write_rate_bytes_per_second"
    }
}

struct DatabaseBackup: Decodable, Identifiable, Hashable, Sendable {
    var id: String { "\(origin?.id ?? "unknown"):\(path)" }
    var origin: CoordinatorOrigin? = nil
    var path: String
    var size: Int?
    var modifiedAt: String?
    var manifest: String?
    var database: String?
    var container: String?
    var format: String?
    var sha256: String?

    enum CodingKeys: String, CodingKey {
        case path, size, manifest, database, container, format, sha256
        case modifiedAt = "modified_at"
    }

    var verificationCacheKey: String {
        [
            origin?.id ?? "unknown",
            path,
            size.map(String.init) ?? "unknown-size",
            modifiedAt ?? "unknown-modified-at",
            manifest ?? "no-manifest",
            sha256 ?? "no-checksum",
        ].joined(separator: "\u{1f}")
    }
}

struct RecentEvent: Decodable, Identifiable, Hashable, Sendable {
    var id: String { "\(origin?.id ?? "unknown")-\(at)-\(type)" }
    var origin: CoordinatorOrigin? = nil
    var at: String
    var type: String
}

struct ServerLogPayload: Decodable {
    var server: ServerLogServer
    var text: String
    var tail: Int?
}

struct ServerLogServer: Decodable {
    var id: String?
    var name: String?
    var project: String?
    var status: String?
    var url: String?
    var port: Int?
    var stoppedAt: String?
    var stoppedReason: String?
    var logPath: String?

    enum CodingKeys: String, CodingKey {
        case id, name, project, status, url, port
        case stoppedAt = "stopped_at"
        case stoppedReason = "stopped_reason"
        case logPath = "log_path"
    }
}

struct ProjectRuntimeReport: Decodable, Hashable {
    var action: String?
    var ok: Bool?
    var partial: Bool?
    var classification: String?
    var classifications: [String]?
    var project: String?
    var runtimeID: String?
    var name: String?
    var configPath: String?
    var declared: Bool?
    var urls: [ProjectRuntimeURL]
    var ports: [ProjectRuntimePort]
    var services: [ProjectRuntimeService]
    var healthChecks: [ProjectRuntimeHealthCheck]
    var previousExitReasons: [ProjectRuntimeExitReason]
    var logs: [ProjectRuntimeLog]
    var actionErrors: [ProjectRuntimeActionError]?

    enum CodingKeys: String, CodingKey {
        case action, ok, partial, classification, classifications, project, name, declared, urls, ports, services, logs
        case runtimeID = "runtime_id"
        case configPath = "config_path"
        case healthChecks = "health_checks"
        case previousExitReasons = "previous_exit_reasons"
        case actionErrors = "action_errors"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard values.contains(.action) || values.contains(.project) || values.contains(.runtimeID) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "JSON is not a project runtime report")
            )
        }
        action = try values.decodeIfPresent(String.self, forKey: .action)
        ok = try values.decodeIfPresent(Bool.self, forKey: .ok)
        partial = try values.decodeIfPresent(Bool.self, forKey: .partial)
        classification = try values.decodeIfPresent(String.self, forKey: .classification)
        classifications = try values.decodeIfPresent([String].self, forKey: .classifications)
        project = try values.decodeIfPresent(String.self, forKey: .project)
        runtimeID = try values.decodeIfPresent(String.self, forKey: .runtimeID)
        name = try values.decodeIfPresent(String.self, forKey: .name)
        configPath = try values.decodeIfPresent(String.self, forKey: .configPath)
        declared = try values.decodeIfPresent(Bool.self, forKey: .declared)
        urls = try values.decodeIfPresent([ProjectRuntimeURL].self, forKey: .urls) ?? []
        ports = try values.decodeIfPresent([ProjectRuntimePort].self, forKey: .ports) ?? []
        services = try values.decodeIfPresent([ProjectRuntimeService].self, forKey: .services) ?? []
        healthChecks = try values.decodeIfPresent([ProjectRuntimeHealthCheck].self, forKey: .healthChecks) ?? []
        previousExitReasons = try values.decodeIfPresent([ProjectRuntimeExitReason].self, forKey: .previousExitReasons) ?? []
        logs = try values.decodeIfPresent([ProjectRuntimeLog].self, forKey: .logs) ?? []
        actionErrors = try values.decodeIfPresent([ProjectRuntimeActionError].self, forKey: .actionErrors)
    }

    var requiresDockerRuntime: Bool {
        services.contains { service in
            if let container = service.container?.trimmingCharacters(in: .whitespacesAndNewlines),
               !container.isEmpty
            {
                return true
            }
            let type = service.type?.lowercased() ?? ""
            return ["docker", "compose", "container", "postgres", "database"].contains {
                type.contains($0)
            }
        }
    }
}

struct ProjectRuntimeURL: Decodable, Hashable {
    var name: String?
    var url: String?
    var healthURL: String?

    enum CodingKeys: String, CodingKey {
        case name, url
        case healthURL = "health_url"
    }
}

struct ProjectRuntimePort: Decodable, Hashable {
    var name: String?
    var port: Int?
    var fixedPort: Int?
    var ports: String?

    enum CodingKeys: String, CodingKey {
        case name, port, ports
        case fixedPort = "fixed_port"
    }
}

struct ProjectRuntimeService: Decodable, Identifiable, Hashable {
    var id: String { "\(type ?? "service"):\(name ?? container ?? url ?? status ?? "unknown")" }
    var type: String?
    var name: String?
    var role: String?
    var container: String?
    var required: Bool?
    var status: String?
    var ok: Bool?
    var classification: String?
    var message: String?
    var url: String?
    var healthURL: String?
    var port: Int?
    var fixedPort: Int?
    var ports: String?
    var image: String?
    var pid: Int?
    var logPath: String?
    var stoppedAt: String?
    var previousExitReason: String?
    var recentLogs: String?

    enum CodingKeys: String, CodingKey {
        case type, name, role, container, required, status, ok, classification, message, url, port, ports, image, pid
        case healthURL = "health_url"
        case fixedPort = "fixed_port"
        case logPath = "log_path"
        case stoppedAt = "stopped_at"
        case previousExitReason = "previous_exit_reason"
        case recentLogs = "recent_logs"
    }
}

struct ProjectRuntimeHealthCheck: Decodable, Hashable {
    var name: String?
    var type: String?
    var url: String?
    var host: String?
    var port: Int?
    var required: Bool?
    var ok: Bool?
    var status: Int?
    var classification: String?
    var error: String?
}

struct ProjectRuntimeExitReason: Decodable, Hashable {
    var name: String?
    var reason: String?
    var stoppedAt: String?

    enum CodingKeys: String, CodingKey {
        case name, reason
        case stoppedAt = "stopped_at"
    }
}

struct ProjectRuntimeLog: Decodable, Hashable {
    var name: String?
    var text: String?
}

struct ProjectRuntimeActionError: Decodable, Hashable {
    var name: String?
    var classification: String?
    var error: String?
}

enum ServiceFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case running = "Running"
    case unhealthy = "Unhealthy"
    case stopped = "Stopped"

    var id: String { rawValue }
}

enum ResourceTab: String, CaseIterable, Identifiable {
    case servers = "Dev Servers"
    case docker = "Docker"
    case databases = "Databases"

    var id: String { rawValue }

    var systemImage: String {
        switch self {
        case .servers: return "terminal"
        case .docker: return "shippingbox"
        case .databases: return "cylinder.split.1x2"
        }
    }
}

enum SidebarSelection: Hashable {
    case project(String)
    case server(String)
    case docker(String)
    case database(String)
}

extension DockerContainer {
    var stableID: String {
        "\(origin?.id ?? "unknown"):\(id ?? name ?? "\(image ?? "container"):\(ports ?? ""):\(status ?? "")"):\(database ?? "container")"
    }

    /// User-facing selection follows the physical container, not whichever
    /// coordinator observation currently supplies the actionable row. Only an
    /// immutable Docker ID may cross that source boundary; weaker evidence
    /// remains source-qualified so unrelated containers cannot collapse.
    var containerSelectionID: String {
        if let immutableID = id?.trimmingCharacters(in: .whitespacesAndNewlines),
           !immutableID.isEmpty
        {
            return "container:\(immutableID)"
        }
        return "container-observation:\(stableID)"
    }

    /// One physical PostgreSQL container can expose several databases, so the
    /// database name remains part of the logical row identity.
    var databaseSelectionID: String {
        let databaseName = database?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return "\(containerSelectionID)|database|\(databaseName?.isEmpty == false ? databaseName! : "unknown")"
    }

    var isRunning: Bool {
        isRunningStatus(status)
    }

    var isPostgresLike: Bool {
        let haystack = [name, image, ports].compactMap { $0?.lowercased() }.joined(separator: " ")
        return haystack.contains("postgres") || haystack.contains("postgis") || haystack.contains("5432")
    }

    var resourceIdentity: ResourceIdentity? {
        guard ownershipError == nil else { return nil }
        return origin.map {
            ResourceIdentity(
                origin: $0,
                kind: isPostgresLike ? .database : .docker,
                nativeID: id ?? name ?? stableID
            )
        }
    }

    var databaseIdentity: DatabaseIdentity? {
        guard let origin,
              let container = name,
              let database,
              !database.isEmpty,
              let containerID = id,
              !containerID.isEmpty
        else { return nil }
        return DatabaseIdentity(origin: origin, container: container, database: database, containerID: containerID)
    }
}

extension PortLease {
    var resourceIdentity: ResourceIdentity? {
        origin.map { ResourceIdentity(origin: $0, kind: .lease, nativeID: coordinatorID ?? id) }
    }
}

func isRunningStatus(_ status: String?) -> Bool {
    let value = (status ?? "").lowercased()
    return value.hasPrefix("up") || value == "running"
}

func isStoppedStatus(_ status: String?) -> Bool {
    let value = (status ?? "").lowercased()
    return value.contains("exited") || value.contains("created") || value.contains("dead") || value.contains("stopped")
}

func canStopStatus(_ status: String?) -> Bool {
    let value = (status ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return !value.isEmpty && !isStoppedStatus(value)
}

func canStopServer(_ server: ManagedServer) -> Bool {
    if isStoppedStatus(server.status) {
        return false
    }
    return canStopStatus(server.status) || server.health?.pidAlive == true
}

extension ManagedServer {
    var logicalKey: String {
        let projectPart = (project ?? cwd ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let namePart = name
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return "\(origin?.id ?? "unknown")::\(projectPart)::\(namePart)"
    }

    var currentURL: String? {
        urlIsCurrent == false ? nil : url
    }

    var resourceIdentity: ResourceIdentity? {
        guard ownershipError == nil else { return nil }
        return origin.map { ResourceIdentity(origin: $0, kind: .server, nativeID: coordinatorID ?? id) }
    }

    func uptime(now: Date) -> UptimeValue {
        UptimeValue(startedAt: createdTs.map { Date(timeIntervalSince1970: $0) }, now: now)
    }
}

extension DockerContainer {
    func uptime(now: Date) -> UptimeValue {
        UptimeValue(startedAt: startedAt.flatMap(parseISOTimestamp), now: now)
    }
}

func parseISOTimestamp(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = formatter.date(from: value) { return date }
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: value)
}

func deduplicatedManagedServers(_ servers: [ManagedServer]) -> [ManagedServer] {
    let grouped = Dictionary(grouping: servers, by: \.logicalKey)
    var winnersByKey: [String: ManagedServer] = [:]

    for (key, bucket) in grouped {
        guard var winner = bucket.max(by: { managedServerRank($0) < managedServerRank($1) }) else { continue }
        if bucket.count > 1 {
            winner.duplicateCount = max(winner.duplicateCount ?? 1, bucket.count)
            winner.duplicateServerIDs = bucket.map(\.id).filter { $0 != winner.id }
        }
        winnersByKey[key] = winner
    }

    return servers.compactMap { server in
        guard let winner = winnersByKey[server.logicalKey], winner.id == server.id else { return nil }
        return winner
    }
}

private func managedServerRank(_ server: ManagedServer) -> (Int, String, String) {
    let status = (server.status ?? "").lowercased()
    let stateRank: Int
    if status == "running" || server.health?.ok == true {
        stateRank = 4
    } else if status == "starting" || status == "unhealthy" || status == "degraded" {
        stateRank = 3
    } else if server.health?.pidAlive == true {
        stateRank = 2
    } else if status == "stopped" {
        stateRank = 1
    } else {
        stateRank = 0
    }
    return (stateRank, server.updatedAt ?? server.stoppedAt ?? "", server.id)
}

// MARK: - Source-aware, testable operations core

/// Match the coordinator readiness verifier's non-strict `realpath` identity.
/// Resolve the deepest existing ancestor, then append any not-yet-created
/// suffix so configuring a future coordinator home remains supported.
private func canonicalCoordinatorHomePath(_ home: String) -> String {
    let standardized = URL(fileURLWithPath: home).standardizedFileURL.path
    var probe = standardized
    var unresolvedSuffix: [String] = []

    while true {
        if let resolvedAncestor = probe.withCString({ pointer -> String? in
            guard let resolved = realpath(pointer, nil) else { return nil }
            defer { free(resolved) }
            return String(cString: resolved)
        }) {
            return unresolvedSuffix.reversed().reduce(
                URL(fileURLWithPath: resolvedAncestor, isDirectory: true)
            ) { partial, component in
                partial.appendingPathComponent(component)
            }.standardizedFileURL.path
        }
        guard probe != "/" else { return standardized }
        let probeURL = URL(fileURLWithPath: probe)
        unresolvedSuffix.append(probeURL.lastPathComponent)
        probe = probeURL.deletingLastPathComponent().path
    }
}

struct CoordinatorOrigin: Codable, Hashable, Sendable, Identifiable {
    let id: String
    let label: String
    let home: String
    var statePath: String?

    init(label: String, home: String, statePath: String? = nil) {
        let normalizedHome = canonicalCoordinatorHomePath(home)
        self.id = normalizedHome
        self.label = label
        self.home = normalizedHome
        self.statePath = statePath
    }

    static func == (lhs: CoordinatorOrigin, rhs: CoordinatorOrigin) -> Bool {
        lhs.id == rhs.id
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

enum CoordinatorRefreshMode: String, Codable, Hashable, Sendable {
    case manual
    case interval
}

struct CoordinatorRefreshPolicy: Codable, Hashable, Sendable {
    static let defaultIntervalSeconds = 30.0

    var mode: CoordinatorRefreshMode
    var intervalSeconds: Double?

    static let `default` = CoordinatorRefreshPolicy(
        mode: .interval,
        intervalSeconds: defaultIntervalSeconds
    )

    static func manual() -> CoordinatorRefreshPolicy {
        CoordinatorRefreshPolicy(mode: .manual, intervalSeconds: nil)
    }

    static func interval(seconds: Double) -> CoordinatorRefreshPolicy {
        CoordinatorRefreshPolicy(mode: .interval, intervalSeconds: seconds)
    }

    func validated() throws -> CoordinatorRefreshPolicy {
        switch mode {
        case .manual:
            guard intervalSeconds == nil else {
                throw CoordinatorConfigurationError.invalidRefreshPolicy("manual refresh must not declare an interval")
            }
            return self
        case .interval:
            guard let intervalSeconds, intervalSeconds.isFinite, (1...3600).contains(intervalSeconds) else {
                throw CoordinatorConfigurationError.invalidRefreshPolicy("refresh interval must be between 1 and 3600 seconds")
            }
            return self
        }
    }
}

struct CoordinatorSourceConfiguration: Codable, Hashable, Sendable, Identifiable {
    var id: String { normalizedHome }
    var label: String
    var home: String
    var enabled: Bool

    init(label: String, home: String, enabled: Bool = true) {
        self.label = label
        self.home = home
        self.enabled = enabled
    }

    var normalizedHome: String {
        canonicalCoordinatorHomePath(home)
    }

    func validated() throws -> CoordinatorSourceConfiguration {
        let cleanLabel = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanHome = home.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanLabel.isEmpty else { throw CoordinatorConfigurationError.invalidSource("source label is empty") }
        guard cleanHome.hasPrefix("/") else { throw CoordinatorConfigurationError.invalidSource("source home must be an absolute path") }
        return CoordinatorSourceConfiguration(
            label: cleanLabel,
            home: canonicalCoordinatorHomePath(cleanHome),
            enabled: enabled
        )
    }

    var origin: CoordinatorOrigin {
        CoordinatorOrigin(label: label, home: normalizedHome)
    }
}

struct CoordinatorConfiguration: Codable, Hashable, Sendable {
    static let currentSchemaVersion = 1

    var schemaVersion: Int
    var sources: [CoordinatorSourceConfiguration]
    var refreshPolicy: CoordinatorRefreshPolicy

    init(
        schemaVersion: Int = CoordinatorConfiguration.currentSchemaVersion,
        sources: [CoordinatorSourceConfiguration] = [],
        refreshPolicy: CoordinatorRefreshPolicy = .default
    ) {
        self.schemaVersion = schemaVersion
        self.sources = sources
        self.refreshPolicy = refreshPolicy
    }

    func validated() throws -> CoordinatorConfiguration {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw CoordinatorConfigurationError.unsupportedSchema(schemaVersion)
        }
        let normalized = try sources.map { try $0.validated() }
        var seen = Set<String>()
        for source in normalized where !seen.insert(source.normalizedHome).inserted {
            throw CoordinatorConfigurationError.duplicateSource(source.normalizedHome)
        }
        return CoordinatorConfiguration(
            schemaVersion: schemaVersion,
            sources: normalized.sorted { $0.normalizedHome < $1.normalizedHome },
            refreshPolicy: try refreshPolicy.validated()
        )
    }

    var enabledOrigins: [CoordinatorOrigin] {
        sources.filter(\.enabled).map(\.origin)
    }
}

enum CoordinatorConfigurationError: LocalizedError, Equatable {
    case unsupportedSchema(Int)
    case invalidSource(String)
    case duplicateSource(String)
    case invalidRefreshPolicy(String)
    case unreadable(String)
    case writeFailed(String)

    var errorDescription: String? {
        switch self {
        case .unsupportedSchema(let version): return "unsupported coordinator configuration schema \(version)"
        case .invalidSource(let message): return "invalid coordinator source: \(message)"
        case .duplicateSource(let path): return "duplicate coordinator source: \(path)"
        case .invalidRefreshPolicy(let message): return "invalid refresh policy: \(message)"
        case .unreadable(let message): return "coordinator configuration is unreadable: \(message)"
        case .writeFailed(let message): return "could not save coordinator configuration: \(message)"
        }
    }
}

struct CoordinatorConfigurationLoadResult: Sendable {
    let configuration: CoordinatorConfiguration?
    let warning: String?
    let usedLastKnownGood: Bool
}

protocol CoordinatorConfigurationPersisting: Sendable {
    func load() -> CoordinatorConfigurationLoadResult
    func save(_ configuration: CoordinatorConfiguration) throws
}

/// LaunchServices can remap HOME/CFFIXED_USER_HOME for an app process. The
/// effective account's passwd record remains the authoritative user root.
struct POSIXAccountHomeResolver: Sendable {
    private let resolveAccountHome: @Sendable () -> String?

    init(
        resolveAccountHome: @escaping @Sendable () -> String? = POSIXAccountHomeResolver.effectiveAccountHome
    ) {
        self.resolveAccountHome = resolveAccountHome
    }

    func resolve() -> String? {
        guard let rawValue = resolveAccountHome() else { return nil }
        let candidate = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard candidate.hasPrefix("/") else { return nil }
        return URL(fileURLWithPath: candidate).standardizedFileURL.path
    }

    private static func effectiveAccountHome() -> String? {
        let effectiveUserID = geteuid()
        var bufferSize = 16 * 1_024
        while bufferSize <= 1_024 * 1_024 {
            var account = passwd()
            var accountPointer: UnsafeMutablePointer<passwd>?
            var buffer = [CChar](repeating: 0, count: bufferSize)
            let lookup = buffer.withUnsafeMutableBufferPointer { bytes -> (status: Int32, path: String?) in
                guard let baseAddress = bytes.baseAddress else { return (EINVAL, nil) }
                let status = getpwuid_r(
                    effectiveUserID,
                    &account,
                    baseAddress,
                    bytes.count,
                    &accountPointer
                )
                guard status == 0,
                      accountPointer != nil,
                      let directory = account.pw_dir
                else { return (status, nil) }
                return (status, String(cString: directory))
            }
            if lookup.status == ERANGE {
                bufferSize *= 2
                continue
            }
            guard lookup.status == 0,
                  let path = lookup.path,
                  !path.isEmpty
            else { return nil }
            return path
        }
        return nil
    }
}

struct PrivateCoordinatorConfigurationStore: CoordinatorConfigurationPersisting, Sendable {
    enum TransactionEvent: Sendable {
        case waitingForExclusiveLock
        case acquiredExclusiveLock
        case replacedLastKnownGood
        case replacedPrimary
    }

    let configurationURL: URL
    let lastKnownGoodURL: URL
    private let storageUnavailableReason: String?
    private let legacyConfigurationURL: URL?
    private let legacyLastKnownGoodURL: URL?
    private let transactionObserver: @Sendable (TransactionEvent) throws -> Void

    init(
        configurationURL: URL? = nil,
        accountHomeResolver: POSIXAccountHomeResolver = POSIXAccountHomeResolver(),
        legacyConfigurationURL: URL = (
            FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
                .appendingPathComponent("CodexOpsConsole", isDirectory: true)
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/CodexOpsConsole", isDirectory: true)
        ).appendingPathComponent("coordinator-configuration.json"),
        transactionObserver: @escaping @Sendable (TransactionEvent) throws -> Void = { _ in }
    ) {
        // Deliberately retain the pre-rename storage identity so existing
        // coordinator-source settings survive the DevOps Board rename.
        let selected: URL
        let legacySelected: URL?
        if let configurationURL {
            selected = configurationURL
            storageUnavailableReason = nil
            legacySelected = nil
        } else if let accountHome = accountHomeResolver.resolve() {
            selected = URL(fileURLWithPath: accountHome, isDirectory: true)
                .appendingPathComponent("Library/Application Support/CodexOpsConsole", isDirectory: true)
                .appendingPathComponent("coordinator-configuration.json")
            storageUnavailableReason = nil
            let standardizedLegacy = legacyConfigurationURL.standardizedFileURL
            legacySelected = standardizedLegacy == selected.standardizedFileURL ? nil : standardizedLegacy
        } else {
            // This URL is never read or written while the resolution error is
            // present; it keeps the public evidence properties non-optional.
            selected = URL(fileURLWithPath: "/var/empty", isDirectory: true)
                .appendingPathComponent("Library/Application Support/CodexOpsConsole", isDirectory: true)
                .appendingPathComponent("coordinator-configuration.json")
            storageUnavailableReason = "the effective POSIX account home could not be resolved"
            legacySelected = nil
        }
        self.configurationURL = selected
        self.lastKnownGoodURL = selected.deletingPathExtension().appendingPathExtension("last-known-good.json")
        self.legacyConfigurationURL = legacySelected
        self.legacyLastKnownGoodURL = legacySelected?.deletingPathExtension().appendingPathExtension("last-known-good.json")
        self.transactionObserver = transactionObserver
    }

    func load() -> CoordinatorConfigurationLoadResult {
        if let storageUnavailableReason {
            return CoordinatorConfigurationLoadResult(
                configuration: nil,
                warning: "Coordinator configuration is unavailable: \(storageUnavailableReason).",
                usedLastKnownGood: false
            )
        }
        do {
            return try withExclusiveTransaction {
                let primary = decode(configurationURL)
                let backup = decode(lastKnownGoodURL)
                if !primary.isMissing || !backup.isMissing {
                    return loadResult(primary: primary, backup: backup)
                }

                guard let legacyConfigurationURL, let legacyLastKnownGoodURL else {
                    return CoordinatorConfigurationLoadResult(
                        configuration: nil,
                        warning: nil,
                        usedLastKnownGood: false
                    )
                }
                let legacyResult = loadResult(
                    primary: decode(legacyConfigurationURL),
                    backup: decode(legacyLastKnownGoodURL)
                )
                guard let configuration = legacyResult.configuration else { return legacyResult }

                do {
                    try persistPairUnderLock(configuration)
                    return legacyResult
                } catch {
                    let migrationWarning = "Could not migrate the legacy coordinator configuration to the POSIX account path: \(error.localizedDescription)"
                    let warning = [legacyResult.warning, migrationWarning]
                        .compactMap { $0 }
                        .joined(separator: " ")
                    return CoordinatorConfigurationLoadResult(
                        configuration: configuration,
                        warning: warning,
                        usedLastKnownGood: legacyResult.usedLastKnownGood
                    )
                }
            }
        } catch {
            return CoordinatorConfigurationLoadResult(
                configuration: nil,
                warning: "Coordinator configuration is unavailable: \(error.localizedDescription)",
                usedLastKnownGood: false
            )
        }
    }

    private func loadResult(primary: DecodeResult, backup: DecodeResult) -> CoordinatorConfigurationLoadResult {
        switch primary {
        case .success(let configuration):
            return CoordinatorConfigurationLoadResult(configuration: configuration, warning: nil, usedLastKnownGood: false)
        case .missing:
            switch backup {
            case .success(let configuration):
                return CoordinatorConfigurationLoadResult(
                    configuration: configuration,
                    warning: "Coordinator configuration is missing; using the last-known-good copy.",
                    usedLastKnownGood: true
                )
            case .missing:
                return CoordinatorConfigurationLoadResult(configuration: nil, warning: nil, usedLastKnownGood: false)
            case .failure(let backupError):
                return CoordinatorConfigurationLoadResult(
                    configuration: nil,
                    warning: "Coordinator configuration is missing and its last-known-good copy is invalid. \(backupError)",
                    usedLastKnownGood: false
                )
            }
        case .failure(let primaryError):
            switch backup {
            case .success(let configuration):
                return CoordinatorConfigurationLoadResult(
                    configuration: configuration,
                    warning: "Coordinator configuration is invalid; using the last-known-good copy. \(primaryError)",
                    usedLastKnownGood: true
                )
            case .missing:
                return CoordinatorConfigurationLoadResult(
                    configuration: nil,
                    warning: "Coordinator configuration is invalid and no last-known-good copy is available. \(primaryError)",
                    usedLastKnownGood: false
                )
            case .failure(let backupError):
                return CoordinatorConfigurationLoadResult(
                    configuration: nil,
                    warning: "Coordinator configuration and its last-known-good copy are invalid. Primary: \(primaryError). Backup: \(backupError)",
                    usedLastKnownGood: false
                )
            }
        }
    }

    func save(_ configuration: CoordinatorConfiguration) throws {
        if let storageUnavailableReason {
            throw CoordinatorConfigurationError.writeFailed(storageUnavailableReason)
        }
        try withExclusiveTransaction {
            try persistPairUnderLock(configuration)
        }
    }

    private func persistPairUnderLock(_ configuration: CoordinatorConfiguration) throws {
        let validated = try configuration.validated()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(validated)
        let originalPrimary = try snapshot(configurationURL)
        let originalLastKnownGood = try snapshot(lastKnownGoodURL)
        do {
            try atomicPrivateWrite(data, to: lastKnownGoodURL)
            try transactionObserver(.replacedLastKnownGood)
            try atomicPrivateWrite(data, to: configurationURL)
            try transactionObserver(.replacedPrimary)
        } catch {
            var rollbackFailures: [String] = []
            for (snapshot, url) in [
                (originalLastKnownGood, lastKnownGoodURL),
                (originalPrimary, configurationURL),
            ] {
                do {
                    try restore(snapshot, to: url)
                } catch {
                    rollbackFailures.append("\(url.lastPathComponent): \(error.localizedDescription)")
                }
            }
            let rollbackDetail = rollbackFailures.isEmpty
                ? "the previous primary and last-known-good pair was restored"
                : "rollback also failed for \(rollbackFailures.joined(separator: "; "))"
            throw CoordinatorConfigurationError.writeFailed("\(error.localizedDescription); \(rollbackDetail)")
        }
    }

    private enum DecodeResult {
        case success(CoordinatorConfiguration)
        case missing
        case failure(String)

        var isMissing: Bool {
            if case .missing = self { return true }
            return false
        }
    }

    private enum StoredFileSnapshot {
        case missing
        case data(Data)
    }

    private func decode(_ url: URL) -> DecodeResult {
        guard FileManager.default.fileExists(atPath: url.path) else { return .missing }
        do {
            let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey])
            guard values.isSymbolicLink != true, values.isRegularFile == true else {
                return .failure("\(url.lastPathComponent) is not a regular file")
            }
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            let decoded = try JSONDecoder().decode(CoordinatorConfiguration.self, from: data)
            return .success(try decoded.validated())
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    private func snapshot(_ url: URL) throws -> StoredFileSnapshot {
        guard FileManager.default.fileExists(atPath: url.path) else { return .missing }
        do {
            let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey])
            guard values.isSymbolicLink != true, values.isRegularFile == true else {
                throw CoordinatorConfigurationError.writeFailed("\(url.lastPathComponent) is not a regular file")
            }
            return .data(try Data(contentsOf: url, options: [.mappedIfSafe]))
        } catch let error as CoordinatorConfigurationError {
            throw error
        } catch {
            throw CoordinatorConfigurationError.writeFailed(error.localizedDescription)
        }
    }

    private func restore(_ snapshot: StoredFileSnapshot, to url: URL) throws {
        switch snapshot {
        case .missing:
            if FileManager.default.fileExists(atPath: url.path) {
                do {
                    try FileManager.default.removeItem(at: url)
                } catch {
                    throw CoordinatorConfigurationError.writeFailed(error.localizedDescription)
                }
            }
        case .data(let data):
            try atomicPrivateWrite(data, to: url)
        }
    }

    /// Every reader and writer uses the same advisory lock. Writers therefore
    /// commit the primary/LKG pair in lock-acquisition order; the last lock
    /// holder is the deterministic last writer and readers never observe the
    /// intermediate replacement of only one member of the pair.
    private func withExclusiveTransaction<T>(_ operation: () throws -> T) throws -> T {
        let directory = configurationURL.deletingLastPathComponent()
        try preparePrivateDirectory(directory)
        try transactionObserver(.waitingForExclusiveLock)
        let lockURL = configurationURL.deletingPathExtension().appendingPathExtension("lock")
        let descriptor = open(
            lockURL.path,
            O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
            mode_t(S_IRUSR | S_IWUSR)
        )
        guard descriptor >= 0 else {
            throw CoordinatorConfigurationError.writeFailed("could not open the configuration transaction lock: \(String(cString: strerror(errno)))")
        }
        defer { close(descriptor) }
        guard fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            throw CoordinatorConfigurationError.writeFailed("could not protect the configuration transaction lock: \(String(cString: strerror(errno)))")
        }
        while flock(descriptor, LOCK_EX) != 0 {
            if errno == EINTR { continue }
            throw CoordinatorConfigurationError.writeFailed("could not acquire the configuration transaction lock: \(String(cString: strerror(errno)))")
        }
        defer { _ = flock(descriptor, LOCK_UN) }
        try transactionObserver(.acquiredExclusiveLock)
        return try operation()
    }

    private func preparePrivateDirectory(_ directory: URL) throws {
        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        } catch {
            throw CoordinatorConfigurationError.writeFailed(error.localizedDescription)
        }
    }

    private func atomicPrivateWrite(_ data: Data, to target: URL) throws {
        let temporary = target.deletingLastPathComponent().appendingPathComponent(".\(target.lastPathComponent).\(UUID().uuidString).tmp")
        let fileManager = FileManager.default
        guard fileManager.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CoordinatorConfigurationError.writeFailed("could not create a private temporary file")
        }
        defer { try? fileManager.removeItem(at: temporary) }
        do {
            let handle = try FileHandle(forWritingTo: temporary)
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            guard rename(temporary.path, target.path) == 0 else {
                throw CoordinatorConfigurationError.writeFailed(String(cString: strerror(errno)))
            }
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            let descriptor = open(target.deletingLastPathComponent().path, O_RDONLY)
            if descriptor >= 0 {
                _ = fsync(descriptor)
                close(descriptor)
            }
        } catch let error as CoordinatorConfigurationError {
            throw error
        } catch {
            throw CoordinatorConfigurationError.writeFailed(error.localizedDescription)
        }
    }
}

enum ResourceKind: String, Codable, Hashable, Sendable {
    case server
    case docker
    case database
    case lease
    case project
}

struct ResourceIdentity: Codable, Hashable, Sendable, Identifiable, Comparable {
    let origin: CoordinatorOrigin
    let kind: ResourceKind
    let nativeID: String

    var id: String { rawValue }
    var rawValue: String { "\(origin.id)|\(kind.rawValue)|\(nativeID)" }

    static func < (lhs: ResourceIdentity, rhs: ResourceIdentity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

enum CoordinatorSourcePhase: String, Codable, Hashable, Sendable {
    case loading
    case loaded
    case failed
    case stale
}

struct CoordinatorSourceState: Codable, Hashable, Sendable, Identifiable {
    var id: String { origin.id }
    let origin: CoordinatorOrigin
    var phase: CoordinatorSourcePhase
    var checkedAt: Date
    var resourceCount: Int
    var error: String?

    init(
        origin: CoordinatorOrigin,
        phase: CoordinatorSourcePhase,
        checkedAt: Date,
        resourceCount: Int = 0,
        error: String? = nil
    ) {
        self.origin = origin
        self.phase = phase
        self.checkedAt = checkedAt
        self.resourceCount = resourceCount
        self.error = error
    }
}

enum CoordinatorCapability: String, Codable, Hashable, Sendable, CaseIterable {
    case coordinator
    case docker
    case database

    var displayName: String {
        switch self {
        case .coordinator: "Coordinator"
        case .docker: "Docker"
        case .database: "Database"
        }
    }
}

enum CoordinatorCapabilityPhase: String, Codable, Hashable, Sendable {
    case loading
    case available
    case unavailable
}

struct CoordinatorCapabilityState: Codable, Hashable, Sendable, Identifiable {
    var id: String { "\(origin.id)|\(capability.rawValue)" }
    let origin: CoordinatorOrigin
    let capability: CoordinatorCapability
    var phase: CoordinatorCapabilityPhase
    var checkedAt: Date
    var error: String?
}

enum HealthLevel: Int, Codable, Hashable, Sendable, Comparable {
    case nominal = 0
    case busy = 1
    case degraded = 2
    case unhealthy = 3
    case unavailable = 4

    static func < (lhs: HealthLevel, rhs: HealthLevel) -> Bool { lhs.rawValue < rhs.rawValue }
}

struct ResourceHealthSignal: Codable, Hashable, Sendable, Identifiable {
    var id: String { identity.rawValue }
    let identity: ResourceIdentity
    let level: HealthLevel
    let reason: String
}

struct HealthSummary: Codable, Hashable, Sendable {
    let level: HealthLevel
    let isComplete: Bool
    let loadedSourceCount: Int
    let failedSourceCount: Int
    let staleSourceCount: Int
    let unhealthyResourceCount: Int
    let failedActionCount: Int
    let runningActionCount: Int
    let generatedAt: Date

    static func reduce(
        sources: [CoordinatorSourceState],
        resourceSignals: [ResourceHealthSignal],
        actions: [RetainedActionResult],
        now: Date
    ) -> HealthSummary {
        let loaded = sources.filter { $0.phase == .loaded }.count
        let failed = sources.filter { $0.phase == .failed }.count
        let stale = sources.filter { $0.phase == .stale }.count
        let staleWithEvidence = sources.filter { $0.phase == .stale && $0.resourceCount > 0 }.count
        let usableSources = loaded + staleWithEvidence
        let unhealthyResources = resourceSignals.filter { $0.level >= .unhealthy }.count
        let failedActions = actions.filter { $0.phase == .failed || $0.phase == .timedOut }.count
        let runningActions = actions.filter { $0.phase == .queued || $0.phase == .running }.count
        let complete = !sources.isEmpty && loaded == sources.count

        let level: HealthLevel
        if sources.isEmpty || usableSources == 0 {
            level = .unavailable
        } else if unhealthyResources > 0 || failedActions > 0 {
            level = .unhealthy
        } else if failed > 0 || stale > 0 || !complete {
            level = .degraded
        } else if runningActions > 0 {
            level = .busy
        } else {
            level = .nominal
        }
        return HealthSummary(
            level: level,
            isComplete: complete,
            loadedSourceCount: loaded,
            failedSourceCount: failed,
            staleSourceCount: stale,
            unhealthyResourceCount: unhealthyResources,
            failedActionCount: failedActions,
            runningActionCount: runningActions,
            generatedAt: now
        )
    }
}

enum OpsIssueKind: String, Codable, Hashable, Sendable {
    case inventory
    case action
    case configuration
}

struct OpsIssue: Codable, Hashable, Sendable, Identifiable {
    let id: UUID
    let kind: OpsIssueKind
    let title: String
    let summary: String
    let details: String
    let createdAt: Date
    let relatedActionID: UUID?

    init(
        id: UUID = UUID(),
        kind: OpsIssueKind,
        title: String,
        summary: String,
        details: String,
        createdAt: Date,
        relatedActionID: UUID? = nil
    ) {
        self.id = id
        self.kind = kind
        self.title = title
        self.summary = summary
        self.details = details
        self.createdAt = createdAt
        self.relatedActionID = relatedActionID
    }
}

struct OpsPresentationSnapshot: Codable, Hashable, Sendable {
    let health: HealthSummary
    let level: HealthLevel
    let statusTitle: String
    let statusMessage: String
    let inventoryIssue: OpsIssue?
    let actionIssue: OpsIssue?
    let sources: [CoordinatorSourceState]
    let capabilities: [CoordinatorCapabilityState]
    let unavailableCapabilityCount: Int

    static func reduce(
        health: HealthSummary,
        sources: [CoordinatorSourceState],
        inventoryIssue: OpsIssue?,
        actionIssue: OpsIssue?,
        capabilities: [CoordinatorCapabilityState] = []
    ) -> OpsPresentationSnapshot {
        var level = health.level
        let unavailableCapabilityCount = capabilities.filter { $0.phase == .unavailable }.count
        if unavailableCapabilityCount > 0 {
            level = max(level, sources.isEmpty ? .unavailable : .degraded)
        }
        if inventoryIssue != nil {
            level = max(level, sources.isEmpty ? .unavailable : .degraded)
        }
        if actionIssue != nil {
            level = max(level, .unhealthy)
        }
        let statusTitle: String
        switch level {
        case .nominal: statusTitle = "All systems nominal"
        case .busy: statusTitle = "Action in progress"
        case .degraded:
            statusTitle = unavailableCapabilityCount > 0 ? "Capabilities degraded" : "Inventory incomplete"
        case .unhealthy: statusTitle = "Action or resource requires attention"
        case .unavailable: statusTitle = "Inventory unavailable"
        }
        let statusMessage = inventoryIssue?.summary
            ?? actionIssue?.summary
            ?? statusTitle
        return OpsPresentationSnapshot(
            health: health,
            level: level,
            statusTitle: statusTitle,
            statusMessage: statusMessage,
            inventoryIssue: inventoryIssue,
            actionIssue: actionIssue,
            sources: sources.sorted { $0.origin.id < $1.origin.id },
            capabilities: capabilities.sorted { $0.id < $1.id },
            unavailableCapabilityCount: unavailableCapabilityCount
        )
    }
}

enum MutationBlockKind: String, Codable, Hashable, Sendable {
    case unknownSource
    case loadingSource
    case staleSource
    case failedSource
    case unknownCapability
    case unavailableCapability
    case duplicateAction
    case staleResource
    case invalidResource
    case confirmationRequired
    case batchLimit
}

struct MutationAvailability: Codable, Hashable, Sendable {
    let isAllowed: Bool
    let blockKind: MutationBlockKind?
    let message: String?

    static let available = MutationAvailability(isAllowed: true, blockKind: nil, message: nil)

    static func blocked(_ kind: MutationBlockKind, _ message: String) -> MutationAvailability {
        MutationAvailability(isAllowed: false, blockKind: kind, message: message)
    }
}

enum ActionKind: String, Codable, Hashable, Sendable {
    case refreshInventory
    case startServer
    case stopServer
    case restartServer
    case serverLogs
    case startDocker
    case stopDocker
    case restartDocker
    case dockerLogs
    case leasePort
    case releasePort
    case projectStatus
    case projectStart
    case projectStop
    case projectRestart
    case backupDatabase
    case verifyBackup
    case restoreDatabase
}

enum ActionPhase: String, Codable, Hashable, Sendable {
    case queued
    case running
    case succeeded
    case failed
    case timedOut
    case cancelled
}

struct ActionRequest: Codable, Hashable, Sendable, Identifiable {
    let id: UUID
    let kind: ActionKind
    let title: String
    let origin: CoordinatorOrigin?
    let resource: ResourceIdentity?
    let leaseID: String?
    let projectPath: String?

    init(
        id: UUID = UUID(),
        kind: ActionKind,
        title: String,
        origin: CoordinatorOrigin? = nil,
        resource: ResourceIdentity? = nil,
        leaseID: String? = nil,
        projectPath: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.title = title
        self.origin = origin ?? resource?.origin
        self.resource = resource
        self.leaseID = leaseID
        self.projectPath = projectPath
    }
}

struct RetainedActionResult: Codable, Hashable, Sendable, Identifiable {
    var id: UUID { request.id }
    let request: ActionRequest
    var phase: ActionPhase
    let queuedAt: Date
    var startedAt: Date?
    var finishedAt: Date?
    var exitStatus: Int32?
    var stdout: String
    var stderr: String
    var failure: String?
    var coordinatorOperationID: String?
    var outputTruncated: Bool

    init(
        request: ActionRequest,
        phase: ActionPhase,
        queuedAt: Date,
        startedAt: Date? = nil,
        finishedAt: Date? = nil,
        exitStatus: Int32? = nil,
        stdout: String = "",
        stderr: String = "",
        failure: String? = nil,
        coordinatorOperationID: String? = nil,
        outputTruncated: Bool = false
    ) {
        self.request = request
        self.phase = phase
        self.queuedAt = queuedAt
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.exitStatus = exitStatus
        self.stdout = stdout
        self.stderr = stderr
        self.failure = failure
        self.coordinatorOperationID = coordinatorOperationID
        self.outputTruncated = outputTruncated
    }
}

enum LogEvidenceState: String, Codable, Hashable, Sendable {
    case loading
    case available
    case empty
    case failed
    case timedOut
    case cancelled
    case unavailable
}

struct RetainedLogEvidence: Codable, Hashable, Sendable, Identifiable {
    var id: String { resource.rawValue }
    let resource: ResourceIdentity
    let actionID: UUID
    let source: CoordinatorOrigin
    let requestedAt: Date
    var completedAt: Date?
    var state: LogEvidenceState
    var displayText: String
    var stdout: String
    var stderr: String
    var exitStatus: Int32?
    var outputTruncated: Bool
}

struct LeaseCommandPayload: Decodable, Hashable, Sendable {
    let id: String
    let port: Int
    let agent: String?
    let project: String?
    let purpose: String?
    let status: String?
    let expiresAtISO: String?
    let serverID: String?
    let pendingOperationID: String?

    enum CodingKeys: String, CodingKey {
        case id, port, agent, project, purpose, status
        case expiresAtISO = "expires_at_iso"
        case serverID = "server_id"
        case pendingOperationID = "pending_operation_id"
    }
}

enum LeaseLifecyclePhase: String, Codable, Hashable, Sendable {
    case active
    case released
    case expired
    case failed
    case unavailable
}

struct LeaseActionResult: Codable, Hashable, Sendable, Identifiable {
    var id: String { identity.rawValue }
    var identity: ResourceIdentity
    let leaseID: String
    let port: Int
    var agent: String?
    let project: String?
    var purpose: String?
    var status: String?
    let expiresAtISO: String?
    var serverID: String?
    var pendingOperationID: String?
    var phase: LeaseLifecyclePhase

    init(origin: CoordinatorOrigin, payload: LeaseCommandPayload, actingAgent: String? = nil) {
        identity = ResourceIdentity(origin: origin, kind: .lease, nativeID: payload.id)
        leaseID = payload.id
        port = payload.port
        agent = payload.agent ?? actingAgent
        project = payload.project
        purpose = payload.purpose
        status = payload.status
        expiresAtISO = payload.expiresAtISO
        serverID = payload.serverID
        pendingOperationID = payload.pendingOperationID
        phase = LeaseActionResult.phase(
            status: payload.status,
            expiresAtISO: payload.expiresAtISO,
            serverID: payload.serverID,
            pendingOperationID: payload.pendingOperationID,
            now: Date()
        )
    }

    init(origin: CoordinatorOrigin, lease: PortLease, now: Date) {
        let nativeID = lease.coordinatorID ?? lease.id
        identity = ResourceIdentity(origin: origin, kind: .lease, nativeID: nativeID)
        leaseID = nativeID
        port = lease.port
        agent = lease.agent
        project = lease.project
        purpose = lease.purpose
        status = lease.status
        expiresAtISO = lease.expiresAtISO
        serverID = lease.serverID
        pendingOperationID = lease.pendingOperationID
        phase = LeaseActionResult.phase(
            status: lease.status,
            expiresAtISO: lease.expiresAtISO,
            serverID: lease.serverID,
            pendingOperationID: lease.pendingOperationID,
            now: now
        )
    }

    mutating func reconcile(
        with lease: PortLease?,
        sourcePhase: CoordinatorSourcePhase?,
        isAuthoritativelyAbsent: Bool,
        now: Date
    ) {
        if phase == .released || phase == .expired || phase == .failed {
            return
        }
        guard sourcePhase == .loaded else {
            phase = .unavailable
            return
        }
        if let lease {
            if let currentOrigin = lease.origin { rebind(origin: currentOrigin) }
            agent = lease.agent
            purpose = lease.purpose
            status = lease.status
            serverID = lease.serverID
            pendingOperationID = lease.pendingOperationID
            phase = Self.phase(
                status: lease.status,
                expiresAtISO: lease.expiresAtISO ?? expiresAtISO,
                serverID: lease.serverID,
                pendingOperationID: lease.pendingOperationID,
                now: now
            )
        } else if isAuthoritativelyAbsent {
            phase = .released
            status = "released"
        } else {
            phase = Self.phase(
                status: status,
                expiresAtISO: expiresAtISO,
                serverID: serverID,
                pendingOperationID: pendingOperationID,
                now: now
            )
        }
    }

    mutating func rebind(origin: CoordinatorOrigin) {
        identity = ResourceIdentity(origin: origin, kind: .lease, nativeID: leaseID)
    }

    var canStartServer: Bool {
        phase == .active
            && serverID == nil
            && pendingOperationID == nil
            && project?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
            && agent?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
            && purpose == "manual"
    }

    var canReleaseDirectly: Bool {
        phase == .active
            && serverID == nil
            && pendingOperationID == nil
            && project?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
    }

    var managementStatus: String {
        guard phase == .active else { return phase.rawValue }
        if pendingOperationID != nil { return "attaching" }
        if serverID != nil { return "attached" }
        return "active"
    }

    static func phase(
        status: String?,
        expiresAtISO: String?,
        serverID: String?,
        pendingOperationID: String?,
        now: Date
    ) -> LeaseLifecyclePhase {
        let normalized = (status ?? "active").lowercased()
        if normalized.contains("release") { return .released }
        if normalized.contains("expir") { return .expired }
        if normalized.contains("fail") { return .failed }
        if serverID != nil || pendingOperationID != nil { return .active }
        if let expiry = expiresAtISO.flatMap(parseISOTimestamp), expiry <= now { return .expired }
        return .active
    }
}

struct DatabaseIdentity: Codable, Hashable, Sendable, Identifiable {
    var id: String { "\(origin.id)|database|\(containerID ?? "unknown-container")|\(container)|\(database)" }
    let origin: CoordinatorOrigin
    let container: String
    let database: String
    let containerID: String?

    init(origin: CoordinatorOrigin, container: String, database: String, containerID: String? = nil) {
        self.origin = origin
        self.container = container
        self.database = database
        self.containerID = containerID
    }

    func isSameImmutableDatabase(as other: DatabaseIdentity) -> Bool {
        guard origin.id == other.origin.id,
              container == other.container,
              database == other.database,
              let leftID = containerID,
              let rightID = other.containerID,
              !leftID.isEmpty,
              !rightID.isEmpty
        else { return false }
        return leftID == rightID || leftID.hasPrefix(rightID) || rightID.hasPrefix(leftID)
    }
}

enum ChecksumState: String, Codable, Hashable, Sendable {
    case unknown
    case verified
    case failed
}

enum RestoreTestState: String, Codable, Hashable, Sendable {
    case notRun
    case passed
    case failed
}

struct BackupRecord: Codable, Hashable, Sendable, Identifiable {
    var id: String { "\(identity.id)|\(path)" }
    let identity: DatabaseIdentity
    let path: String
    let createdAt: Date
    let checksum: ChecksumState
    let restoreTest: RestoreTestState
    var format: String?
    var scope: String?
    var compatibilityError: String?

    var isStronglyVerified: Bool {
        checksum == .verified && restoreTest == .passed && compatibilityError == nil
    }
}

struct BackupManifestV2: Decodable, Sendable {
    struct Source: Decodable, Sendable {
        struct Container: Decodable, Sendable {
            let name: String?
            let id: String?
            let image: String?
        }
        struct Postgres: Decodable, Sendable {
            let database: String?
            let scope: String?
        }
        let container: Container?
        let postgres: Postgres?
    }
    struct Verification: Decodable, Sendable {
        let verifiedAt: String?
        let mode: String?
        let scope: String?
        let sha256: String?
        let ok: Bool?

        enum CodingKeys: String, CodingKey {
            case mode, scope, sha256, ok
            case verifiedAt = "verified_at"
        }
    }

    let schemaVersion: Int?
    let createdAt: String?
    let scope: String?
    let format: String?
    let sha256: String?
    let source: Source?
    let verification: Verification?
    let container: String?
    let database: String?

    enum CodingKeys: String, CodingKey {
        case scope, format, sha256, source, verification, container, database
        case schemaVersion = "schema_version"
        case createdAt = "created_at"
    }
}

extension DatabaseBackup {
    func verifiedRecord() -> BackupRecord? {
        record(verifyArtifactChecksum: true)
    }

    func manifestRecord() -> BackupRecord? {
        record(verifyArtifactChecksum: false)
    }

    private func record(verifyArtifactChecksum: Bool) -> BackupRecord? {
        guard let origin, let manifest, let data = FileManager.default.contents(atPath: manifest),
              let descriptor = try? JSONDecoder().decode(BackupManifestV2.self, from: data)
        else { return nil }
        guard let containerName = descriptor.source?.container?.name ?? descriptor.container,
              let databaseName = descriptor.source?.postgres?.database ?? descriptor.database,
              !containerName.isEmpty,
              !databaseName.isEmpty
        else { return nil }

        let verification = descriptor.verification
        let currentChecksum = verifyArtifactChecksum ? fileSHA256(path) : nil
        let checksumMatches = verification?.ok == true
            && verification?.sha256 != nil
            && verification?.sha256 == descriptor.sha256
            && currentChecksum == descriptor.sha256
        let checksumState: ChecksumState
        if !verifyArtifactChecksum {
            checksumState = .unknown
        } else if let expected = descriptor.sha256, let currentChecksum, currentChecksum != expected {
            checksumState = .failed
        } else if checksumMatches {
            checksumState = .verified
        } else if verification?.ok == false {
            checksumState = .failed
        } else {
            checksumState = .unknown
        }
        let restoreState: RestoreTestState
        if verification?.ok == false {
            restoreState = .failed
        } else if verification?.mode == "test_restore" && verification?.ok == true {
            restoreState = .passed
        } else {
            restoreState = .notRun
        }
        let created = descriptor.createdAt.flatMap(parseISOTimestamp)
            ?? modifiedAt.flatMap(parseISOTimestamp)
            ?? Date.distantPast
        let manifestContainerID = descriptor.source?.container?.id
        let compatibilityError: String?
        if descriptor.schemaVersion != 2 {
            compatibilityError = "unsupported or missing manifest schema"
        } else if manifestContainerID?.isEmpty != false {
            compatibilityError = "immutable source container id is unavailable"
        } else {
            compatibilityError = nil
        }
        return BackupRecord(
            identity: DatabaseIdentity(origin: origin, container: containerName, database: databaseName, containerID: manifestContainerID),
            path: path,
            createdAt: created,
            checksum: checksumState,
            restoreTest: restoreState,
            format: descriptor.format ?? format,
            scope: descriptor.scope,
            compatibilityError: compatibilityError
        )
    }
}

func fileSHA256(_ path: String) -> String? {
    guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
    defer { try? handle.close() }
    var hasher = SHA256()
    do {
        while try autoreleasepool(invoking: {
            guard let chunk = try handle.read(upToCount: 1_048_576), !chunk.isEmpty else {
                return false
            }
            hasher.update(data: chunk)
            return true
        }) {
            // The autorelease pool bounds Foundation Data retained by long
            // multi-gigabyte verification reads.
        }
    } catch {
        return nil
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
}

func newestVerifiedBackup(for identity: DatabaseIdentity, in records: [BackupRecord]) -> BackupRecord? {
    records
        .filter { $0.identity.isSameImmutableDatabase(as: identity) && $0.isStronglyVerified }
        .max { $0.createdAt < $1.createdAt }
}

struct BulkSelection: Codable, Hashable, Sendable {
    private(set) var selected: [ResourceIdentity] = []

    mutating func select(_ identity: ResourceIdentity) {
        guard !selected.contains(identity) else { return }
        selected.append(identity)
        selected.sort()
    }

    mutating func deselect(_ identity: ResourceIdentity) {
        selected.removeAll { $0 == identity }
    }

    mutating func clear() { selected.removeAll() }
    func contains(_ identity: ResourceIdentity) -> Bool { selected.contains(identity) }
}

struct BulkActionResult: Codable, Hashable, Sendable {
    let selection: BulkSelection
    let results: [ResourceIdentity: RetainedActionResult]

    var succeededCount: Int { results.values.filter { $0.phase == .succeeded }.count }
    var failedCount: Int { results.values.filter { $0.phase == .failed || $0.phase == .timedOut }.count }
}

struct BulkStopPlanItem: Codable, Hashable, Sendable, Identifiable {
    var id: String { identity.rawValue }
    let identity: ResourceIdentity
    let expectedStatus: String
    let project: String
    let displayName: String
    let sourceCheckedAt: Date
}

struct BulkStopPlan: Codable, Hashable, Sendable, Identifiable {
    let id: UUID
    let preparedAt: Date
    let items: [BulkStopPlanItem]
    let fingerprint: String
    let confirmationText: String

    init(id: UUID = UUID(), preparedAt: Date, items: [BulkStopPlanItem]) {
        self.id = id
        self.preparedAt = preparedAt
        self.items = items.sorted { $0.identity < $1.identity }
        self.fingerprint = bulkStopFingerprint(items: self.items)
        self.confirmationText = "STOP \(items.count) SELECTED"
    }

    var selection: BulkSelection {
        var result = BulkSelection()
        for item in items { result.select(item.identity) }
        return result
    }
}

func bulkStopFingerprint(items: [BulkStopPlanItem]) -> String {
    let material = items.sorted { $0.identity < $1.identity }.map { item in
        [
            item.identity.rawValue,
            item.expectedStatus,
            item.project,
            String(item.sourceCheckedAt.timeIntervalSince1970),
        ].joined(separator: "\u{1f}")
    }.joined(separator: "\u{1e}")
    return SHA256.hash(data: Data(material.utf8)).map { String(format: "%02x", $0) }.joined()
}

struct RestoreVerificationPayload: Decodable, Hashable, Sendable {
    let testRestore: Bool?
    let scratchCreated: Bool?
    let restoreReturncode: Int?

    enum CodingKeys: String, CodingKey {
        case testRestore = "test_restore"
        case scratchCreated = "scratch_created"
        case restoreReturncode = "restore_returncode"
    }

    var provesStrongVerification: Bool {
        testRestore == true && scratchCreated == true && restoreReturncode == 0
    }
}

struct RestoreSafetyBackupPayload: Decodable, Hashable, Sendable {
    let backup: String?
    let manifest: String?
    let sha256: String?
}

struct ContainerIdentityPreflightPayload: Codable, Hashable, Sendable {
    let phase: String?
    let expectedID: String?
    let actualID: String?
    let match: String?
    let executionTarget: String?

    enum CodingKeys: String, CodingKey {
        case phase, match
        case expectedID = "expected_id"
        case actualID = "actual_id"
        case executionTarget = "execution_target"
    }

    func proves(expectedContainerID: String) -> Bool {
        let expected = expectedContainerID.lowercased()
        guard executionTarget == "immutable_full_id",
              let actual = actualID?.lowercased(), actual.count == 64,
              let evidenceExpected = expectedID?.lowercased()
        else { return false }
        if expected.count == 64 {
            return actual == expected && evidenceExpected == expected && match == "exact_full"
        }
        if expected.count == 12 {
            guard actual.hasPrefix(expected) else { return false }
            if evidenceExpected == expected {
                return match == "unambiguous_standard_short"
            }
            return evidenceExpected == actual && match == "exact_full"
        }
        return false
    }
}

struct RestoreCommandPayload: Decodable, Hashable, Sendable {
    let restored: String?
    let container: String?
    let database: String?
    let transactional: Bool?
    let incomingVerification: RestoreVerificationPayload?
    let safetyBackup: RestoreSafetyBackupPayload?
    let safetyVerification: RestoreVerificationPayload?
    let restoredCatalogSignature: [String: Int]?
    let containerIdentityPreflights: [ContainerIdentityPreflightPayload]?

    enum CodingKeys: String, CodingKey {
        case restored, container, database, transactional
        case incomingVerification = "incoming_verification"
        case safetyBackup = "safety_backup"
        case safetyVerification = "safety_verification"
        case restoredCatalogSignature = "restored_catalog_signature"
        case containerIdentityPreflights = "container_identity_preflights"
    }
}

struct DatabaseRestoreEvidence: Codable, Hashable, Sendable, Identifiable {
    var id: String { target.id }
    let target: DatabaseIdentity
    let restoredBackupPath: String
    let safetyBackupPath: String
    let safetyBackupManifest: String?
    let safetyBackupSHA256: String?
    let incomingVerificationPassed: Bool
    let safetyVerificationPassed: Bool
    let transactional: Bool
    let restoredCatalogSignature: [String: Int]
    let containerIdentityPreflights: [ContainerIdentityPreflightPayload]
    let actionID: UUID
    let completedAt: Date
}

enum UptimeValue: Hashable, Sendable {
    case measured(TimeInterval)
    case unavailable(String)

    init(startedAt: Date?, now: Date) {
        guard let startedAt else {
            self = .unavailable("start time unavailable")
            return
        }
        self = .measured(max(0, now.timeIntervalSince(startedAt)))
    }
}

protocol Clock: Sendable {
    func now() -> Date
}

struct SystemClock: Clock {
    func now() -> Date { Date() }
}

enum CommandEnvironment {
    struct PathDirectoryFile: Hashable, Sendable {
        let name: String
        let contents: String
    }

    static func live(
        inherited: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default
    ) -> [String: String] {
        let systemPaths = try? String(contentsOfFile: "/etc/paths", encoding: .utf8)
        let directoryNames = (try? fileManager.contentsOfDirectory(atPath: "/etc/paths.d")) ?? []
        let directoryFiles = directoryNames.sorted().compactMap { name -> PathDirectoryFile? in
            let path = URL(fileURLWithPath: "/etc/paths.d", isDirectory: true)
                .appendingPathComponent(name, isDirectory: false)
                .path
            guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
            return PathDirectoryFile(name: name, contents: contents)
        }
        return resolved(
            inherited: inherited,
            systemPathsFileContents: systemPaths,
            pathDirectoryFiles: directoryFiles
        )
    }

    static func resolved(
        inherited: [String: String],
        systemPathsFileContents: String?,
        pathDirectoryFiles: [PathDirectoryFile]
    ) -> [String: String] {
        var environment = inherited
        let inheritedEntries = pathEntries(inherited["PATH"] ?? "")
        let systemEntries = pathEntries(systemPathsFileContents ?? "", separators: .newlines)
        let directoryEntries = pathDirectoryFiles
            .sorted { $0.name < $1.name }
            .flatMap { pathEntries($0.contents, separators: .newlines) }
        environment["PATH"] = deduplicated(inheritedEntries + systemEntries + directoryEntries)
            .joined(separator: ":")
        return environment
    }

    static func merging(
        base: [String: String],
        overrides: [String: String]
    ) -> [String: String] {
        var environment = base.merging(overrides) { _, override in override }
        let overrideEntries = pathEntries(overrides["PATH"] ?? "")
        let baseEntries = pathEntries(base["PATH"] ?? "")
        environment["PATH"] = deduplicated(overrideEntries + baseEntries).joined(separator: ":")
        return environment
    }

    private static func pathEntries(
        _ value: String,
        separators: CharacterSet = CharacterSet(charactersIn: ":")
    ) -> [String] {
        value.components(separatedBy: separators).compactMap { raw in
            let candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard candidate.hasPrefix("/") else { return nil }
            return URL(fileURLWithPath: candidate).standardizedFileURL.path
        }
    }

    private static func deduplicated(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}

struct CommandRequest: Hashable, Sendable {
    static let defaultMaxOutputBytes = 1_048_576
    static let inventoryMaxOutputBytes = 16 * 1_048_576

    let executable: String
    let arguments: [String]
    let environment: [String: String]
    let currentDirectory: String?
    let timeout: TimeInterval
    let maxOutputBytes: Int

    init(
        executable: String,
        arguments: [String],
        environment: [String: String] = [:],
        currentDirectory: String? = nil,
        timeout: TimeInterval = 120,
        maxOutputBytes: Int = CommandRequest.defaultMaxOutputBytes
    ) {
        self.executable = executable
        self.arguments = arguments
        self.environment = environment
        self.currentDirectory = currentDirectory
        self.timeout = max(0.1, timeout)
        self.maxOutputBytes = max(1, maxOutputBytes)
    }
}

struct CommandExecution: Hashable, Sendable {
    let stdout: String
    let stderr: String
    let exitStatus: Int32
    let timedOut: Bool
    let cancelled: Bool
    let outputTruncated: Bool

    init(
        stdout: String,
        stderr: String,
        exitStatus: Int32,
        timedOut: Bool = false,
        cancelled: Bool = false,
        outputTruncated: Bool = false
    ) {
        self.stdout = stdout
        self.stderr = stderr
        self.exitStatus = exitStatus
        self.timedOut = timedOut
        self.cancelled = cancelled
        self.outputTruncated = outputTruncated
    }
}

protocol CommandExecuting: Sendable {
    func execute(_ request: CommandRequest) async throws -> CommandExecution
}

protocol CoordinatorServing: Sendable {
    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution
}

protocol CoordinatorOriginDiscovering: Sendable {
    func origins() -> [CoordinatorOrigin]
}

struct FileSystemCoordinatorOriginDiscovery: CoordinatorOriginDiscovering, Sendable {
    let environment: [String: String]
    let accountHome: String?

    init(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        accountHomeResolver: POSIXAccountHomeResolver = POSIXAccountHomeResolver()
    ) {
        self.environment = environment
        self.accountHome = accountHomeResolver.resolve()
    }

    func origins() -> [CoordinatorOrigin] {
        let fileManager = FileManager.default
        var candidates: [(String, String)] = []
        if let configured = environment["CODEX_AGENT_COORDINATOR_HOME"], !configured.isEmpty {
            candidates.append(("Configured", configured))
        }
        if let accountHome {
            candidates.append(("Codex", "\(accountHome)/.codex/agent-coordinator"))
            candidates.append(("Claude", "\(accountHome)/.claude/agent-coordinator"))
            let parallRoot = "\(accountHome)/Library/Application Support/Parall"
            if let entries = try? fileManager.contentsOfDirectory(atPath: parallRoot) {
                candidates.append(contentsOf: entries.sorted().map { ("Parall \($0)", "\(parallRoot)/\($0)/.codex/agent-coordinator") })
            }
        }
        var seen = Set<String>()
        return candidates.compactMap { label, path in
            let resolved = canonicalCoordinatorHomePath(path)
            guard seen.insert(resolved).inserted else { return nil }
            var isDirectory: ObjCBool = false
            let exists = fileManager.fileExists(atPath: resolved, isDirectory: &isDirectory)
                || fileManager.fileExists(atPath: "\(resolved)/state.json")
            return exists ? CoordinatorOrigin(label: label, home: resolved) : nil
        }
    }
}

protocol BackupServing: Sendable {
    func execute(origin: CoordinatorOrigin?, arguments: [String]) async throws -> CommandExecution
}

struct DiscoveredDatabase: Codable, Hashable, Sendable, Identifiable {
    var id: String { identity.id }
    let identity: DatabaseIdentity
    let sizeBytes: Int64
}

protocol DatabaseDiscovering: Sendable {
    func discover(origin: CoordinatorOrigin, container: String, containerID: String?) async throws -> [DiscoveredDatabase]
}

struct DockerPostgresDiscoveryService: DatabaseDiscovering, Sendable {
    let executor: any CommandExecuting

    func discover(origin: CoordinatorOrigin, container: String, containerID: String?) async throws -> [DiscoveredDatabase] {
        let environment = ["CODEX_AGENT_COORDINATOR_HOME": origin.home]
        let identity = try await executor.execute(
            CommandRequest(
                executable: "/usr/bin/env",
                arguments: [
                    "docker", "exec", container, "sh", "-c",
                    "printf '%s\\n%s\\n' \"${POSTGRES_USER:-postgres}\" \"${POSTGRES_DB:-postgres}\"",
                ],
                environment: environment
            )
        )
        guard identity.exitStatus == 0 else {
            throw RuntimeError(identity.stderr.isEmpty ? identity.stdout : identity.stderr)
        }
        let identityLines = identity.stdout.split(omittingEmptySubsequences: false, whereSeparator: { $0.isNewline })
        let postgresUser = identityLines.first.map(String.init).flatMap { $0.isEmpty ? nil : $0 } ?? "postgres"
        let connectionDatabase = identityLines.dropFirst().first.map(String.init).flatMap { $0.isEmpty ? nil : $0 } ?? "postgres"
        let query = "SELECT datname, pg_database_size(datname) FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname"
        let catalog = try await executor.execute(
            CommandRequest(
                executable: "/usr/bin/env",
                arguments: [
                    "docker", "exec", container,
                    "psql", "-U", postgresUser, "-d", connectionDatabase,
                    "-At", "-F", "\t", "-c", query,
                ],
                environment: environment
            )
        )
        guard catalog.exitStatus == 0 else {
            throw RuntimeError(catalog.stderr.isEmpty ? catalog.stdout : catalog.stderr)
        }
        return try catalog.stdout.split(whereSeparator: { $0.isNewline }).map { line in
            let fields = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard fields.count == 2, let size = Int64(fields[1]) else {
                throw RuntimeError("Unexpected PostgreSQL catalog row for \(container): \(line)")
            }
            let database = String(fields[0])
            guard !database.isEmpty else { throw RuntimeError("PostgreSQL catalog returned an empty database name") }
            return DiscoveredDatabase(
                identity: DatabaseIdentity(origin: origin, container: container, database: database, containerID: containerID),
                sizeBytes: size
            )
        }
    }
}

struct PythonCoordinatorService: CoordinatorServing, Sendable {
    let executor: any CommandExecuting
    let scriptPath: String

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        let maxOutputBytes = arguments.first == "inventory"
            ? CommandRequest.inventoryMaxOutputBytes
            : CommandRequest.defaultMaxOutputBytes
        return try await executor.execute(
            CommandRequest(
                executable: "/usr/bin/env",
                arguments: ["python3", scriptPath] + arguments,
                environment: ["CODEX_AGENT_COORDINATOR_HOME": origin.home],
                maxOutputBytes: maxOutputBytes
            )
        )
    }
}

struct PythonBackupService: BackupServing, Sendable {
    let executor: any CommandExecuting
    let scriptPath: String

    func execute(origin: CoordinatorOrigin?, arguments: [String]) async throws -> CommandExecution {
        let environment = origin.map { ["CODEX_AGENT_COORDINATOR_HOME": $0.home] } ?? [:]
        return try await executor.execute(
            CommandRequest(executable: "/usr/bin/env", arguments: ["python3", scriptPath] + arguments, environment: environment)
        )
    }
}

enum SkillScript: Sendable {
    case coordinator
    case postgresBackup

    var relativePath: String {
        switch self {
        case .coordinator:
            return "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
        case .postgresBackup:
            return "skills/postgres-docker-backup/scripts/postgres_docker_backup.py"
        }
    }
}

protocol SkillLocating: Sendable {
    func scriptPath(for script: SkillScript) throws -> String
}

struct PortableSkillLocator: SkillLocating, Sendable {
    let environment: [String: String]
    let accountHome: String?
    let currentDirectory: String
    let bundleResourceRoot: String?

    init(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        currentDirectory: String = FileManager.default.currentDirectoryPath,
        bundleResourceRoot: String? = Bundle.main.resourceURL?.path,
        accountHomeResolver: POSIXAccountHomeResolver = POSIXAccountHomeResolver()
    ) {
        self.environment = environment
        self.accountHome = accountHomeResolver.resolve()
        self.currentDirectory = currentDirectory
        self.bundleResourceRoot = bundleResourceRoot
    }

    func scriptPath(for script: SkillScript) throws -> String {
        let fileManager = FileManager.default
        var roots: [String] = []

        // A caller-provided canonical checkout is the only override above the
        // packaged helpers. A launchable .app must otherwise use the scripts
        // whose hashes and signature were verified during packaging before it
        // considers mutable runtime installations.
        if let root = environment["DEVCOORDINATOR_ROOT"], !root.isEmpty { roots.append(root) }
        if let bundleResourceRoot, !bundleResourceRoot.isEmpty { roots.append(bundleResourceRoot) }

        // Bare SwiftPM/development launches can find the repository checkout
        // by walking up from their current directory.
        var cursor = URL(fileURLWithPath: currentDirectory).standardizedFileURL
        while cursor.path != "/" {
            roots.append(cursor.path)
            cursor.deleteLastPathComponent()
        }

        // Installed runtime homes are compatibility fallbacks. They are
        // intentionally below both the packaged resources and a checkout.
        if let codexHome = environment["CODEX_HOME"], !codexHome.isEmpty { roots.append(codexHome) }
        if let claudeHome = environment["CLAUDE_CONFIG_DIR"], !claudeHome.isEmpty { roots.append(claudeHome) }
        if let accountHome {
            roots.append(contentsOf: ["\(accountHome)/.codex", "\(accountHome)/.claude"])
            let parallRoot = "\(accountHome)/Library/Application Support/Parall"
            if let entries = try? fileManager.contentsOfDirectory(atPath: parallRoot) {
                roots.append(contentsOf: entries.sorted().map { "\(parallRoot)/\($0)/.codex" })
            }
        }

        var tried: [String] = []
        var seen = Set<String>()
        for root in roots {
            let normalizedRoot = URL(fileURLWithPath: root).standardizedFileURL.path
            guard seen.insert(normalizedRoot).inserted else { continue }
            let candidate = URL(fileURLWithPath: normalizedRoot).appendingPathComponent(script.relativePath).path
            tried.append(candidate)
            if fileManager.isExecutableFile(atPath: candidate) || fileManager.fileExists(atPath: candidate) {
                return candidate
            }
        }
        throw RuntimeError("Unable to locate \(script.relativePath). Checked:\n\(tried.joined(separator: "\n"))")
    }
}
