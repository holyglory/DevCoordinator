import Foundation

struct Inventory: Decodable {
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
        backups: []
    )
}

struct ManagedURL: Decodable, Identifiable {
    var id: String { "\(project ?? ""):\(name ?? ""):\(url ?? "")" }
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

struct ManagedServer: Decodable, Identifiable, Hashable {
    var id: String
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
    var duplicateCount: Int?
    var duplicateServerIDs: [String]?
    var urlIsCurrent: Bool?
    var portReused: Bool?
    var portReusedBy: PortReuseOwner?

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
        case duplicateCount = "duplicate_count"
        case duplicateServerIDs = "duplicate_server_ids"
        case urlIsCurrent = "url_is_current"
        case portReused = "port_reused"
        case portReusedBy = "port_reused_by"
    }
}

struct PortReuseOwner: Decodable, Hashable {
    var type: String?
    var id: String?
    var name: String?
    var project: String?
    var pid: Int?
    var cwd: String?
    var url: String?
}

struct Health: Decodable, Hashable {
    var ok: Bool?
    var pidAlive: Bool?

    enum CodingKeys: String, CodingKey {
        case ok
        case pidAlive = "pid_alive"
    }
}

struct PortLease: Decodable, Identifiable, Hashable {
    var id: String
    var port: Int
    var agent: String?
    var project: String?
    var purpose: String?
    var status: String?
    var expiresAtISO: String?

    enum CodingKeys: String, CodingKey {
        case id, port, agent, project, purpose, status
        case expiresAtISO = "expires_at_iso"
    }
}

struct DockerSummary: Decodable, Hashable {
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

struct DockerContainer: Decodable, Identifiable, Hashable {
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

    enum CodingKeys: String, CodingKey {
        case id, name, image, status, ports, project, agent, role, adopted, stats
        case metadataSource = "metadata_source"
        case statsHistory = "stats_history"
    }
}

struct DockerStats: Decodable, Identifiable, Hashable {
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

struct DatabaseBackup: Decodable, Identifiable, Hashable {
    var id: String { path }
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
}

struct RecentEvent: Decodable, Identifiable, Hashable {
    var id: String { "\(at)-\(type)" }
    var at: String
    var type: String
}

struct CommandResult {
    var output: String
    var error: String
    var status: Int32
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
        case action, ok, classification, classifications, project, name, declared, urls, ports, services, logs
        case runtimeID = "runtime_id"
        case configPath = "config_path"
        case healthChecks = "health_checks"
        case previousExitReasons = "previous_exit_reasons"
        case actionErrors = "action_errors"
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
        id ?? name ?? "\(image ?? "container"):\(ports ?? ""):\(status ?? "")"
    }

    var isRunning: Bool {
        isRunningStatus(status)
    }

    var isPostgresLike: Bool {
        let haystack = [name, image, ports].compactMap { $0?.lowercased() }.joined(separator: " ")
        return haystack.contains("postgres") || haystack.contains("postgis") || haystack.contains("5432")
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
        return "\(projectPart)::\(namePart)"
    }

    var currentURL: String? {
        urlIsCurrent == false ? nil : url
    }
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
