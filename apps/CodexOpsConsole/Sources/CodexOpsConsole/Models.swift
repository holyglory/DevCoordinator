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
        docker: DockerSummary(available: nil, error: nil, containers: [], postgres: []),
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

    enum CodingKeys: String, CodingKey {
        case id, name, agent, project, cwd, port, host, url, pid, status, health
        case command = "cmd"
        case commandTemplate = "cmd_template"
        case healthURL = "health_url"
        case leaseID = "lease_id"
        case logPath = "log_path"
    }
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
    var containers: [DockerContainer]
    var postgres: [DockerContainer]
}

struct DockerContainer: Decodable, Identifiable, Hashable {
    var id: String?
    var name: String?
    var image: String?
    var status: String?
    var ports: String?
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

struct ActionItem: Identifiable, Hashable {
    enum State: String {
        case running = "Running"
        case queued = "Queued"
        case completed = "Done"
        case failed = "Failed"
    }

    let id = UUID()
    var title: String
    var subtitle: String
    var state: State
    var detail: String?
    var createdAt = Date()
}

struct CommandResult {
    var output: String
    var error: String
    var status: Int32
}

enum ServiceFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case running = "Running"
    case unhealthy = "Unhealthy"
    case stopped = "Stopped"

    var id: String { rawValue }
}
