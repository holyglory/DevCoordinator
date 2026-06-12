import AppKit
import Foundation
import SwiftUI

@MainActor
final class OpsStore: ObservableObject {
    @Published var inventory: Inventory = .empty
    @Published var selectedServerID: ManagedServer.ID?
    @Published var searchText = ""
    @Published var filter: ServiceFilter = .all
    @Published var groupBy = "Category"
    @Published var actionItems: [ActionItem] = []
    @Published var isLoading = false
    @Published var lastError: String?
    @Published var projectPath: String
    @Published var startDraft = StartServerDraft()
    @Published var showingStartSheet = false
    @Published var showingLeaseSheet = false
    @Published var leaseRange = "3000-3999"

    private let coordinatorScript: String
    private let backupScript: String

    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        coordinatorScript = "\(home)/.codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py"
        backupScript = "\(home)/.codex/skills/postgres-docker-backup/scripts/postgres_docker_backup.py"
        projectPath = FileManager.default.currentDirectoryPath
    }

    var selectedServer: ManagedServer? {
        guard let selectedServerID else { return filteredServers.first }
        return inventory.servers.first { $0.id == selectedServerID } ?? filteredServers.first
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
        inventory.coordinatorHome != nil || !inventory.servers.isEmpty || !inventory.leases.isEmpty
    }

    func refresh() {
        Task { await loadInventory() }
    }

    func loadInventory() async {
        isLoading = true
        lastError = nil
        defer { isLoading = false }
        do {
            let result = try await runPython(script: coordinatorScript, arguments: ["inventory", "--project", projectPath])
            try ensureSuccess(result)
            let data = Data(result.output.utf8)
            let decoded = try JSONDecoder().decode(Inventory.self, from: data)
            inventory = decoded
            if selectedServerID == nil {
                selectedServerID = decoded.servers.first?.id
            }
        } catch {
            lastError = error.localizedDescription
            pushAction(title: "Inventory refresh failed", subtitle: projectPath, state: .failed, detail: error.localizedDescription)
        }
    }

    func openURL(_ url: String?) {
        guard let raw = url, let url = URL(string: raw) else { return }
        NSWorkspace.shared.open(url)
    }

    func copyURL(_ url: String?) {
        guard let url else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(url, forType: .string)
        pushAction(title: "Copied URL", subtitle: url, state: .completed)
    }

    func restart(_ server: ManagedServer) {
        runTracked(
            title: "Restart \(server.name)",
            subtitle: server.project ?? projectPath,
            arguments: ["server", "restart", "--project", server.project ?? projectPath, "--name", server.name]
        )
    }

    func stop(_ server: ManagedServer) {
        runTracked(
            title: "Stop \(server.name)",
            subtitle: server.project ?? projectPath,
            arguments: ["server", "stop", "--project", server.project ?? projectPath, "--name", server.name]
        )
    }

    func startServer() {
        var args = [
            "server", "start",
            "--agent", startDraft.agent,
            "--project", startDraft.project.isEmpty ? projectPath : startDraft.project,
            "--name", startDraft.name,
            "--cwd", startDraft.cwd.isEmpty ? projectPath : startDraft.cwd,
            "--cmd", startDraft.command,
            "--range", startDraft.range
        ]
        if !startDraft.healthURL.isEmpty {
            args.append(contentsOf: ["--health-url", startDraft.healthURL])
        }
        runTracked(title: "Start \(startDraft.name)", subtitle: startDraft.project, arguments: args)
        showingStartSheet = false
    }

    func leasePort() {
        let args = [
            "port", "lease",
            "--agent", NSUserName(),
            "--project", projectPath,
            "--range", leaseRange,
            "--purpose", "manual"
        ]
        runTracked(title: "Lease port", subtitle: leaseRange, arguments: args)
        showingLeaseSheet = false
    }

    func backupDatabase(container: DockerContainer?) {
        var args = ["backup", "--out-dir", "\(projectPath)/.codex-db-backups"]
        if let name = container?.name, !name.isEmpty {
            args.append(contentsOf: ["--container", name])
        }
        runTracked(title: "Backup database", subtitle: container?.name ?? "auto-detect Postgres", script: backupScript, arguments: args)
    }

    func dockerLogs(_ container: DockerContainer) {
        guard let name = container.name else { return }
        runTracked(title: "Docker logs", subtitle: name, arguments: ["docker", "logs", "--container", name, "--tail", "80"])
    }

    func restartDocker(_ container: DockerContainer) {
        guard let name = container.name else { return }
        runTracked(title: "Restart container", subtitle: name, arguments: ["docker", "restart", "--container", name])
    }

    func stopDocker(_ container: DockerContainer) {
        guard let name = container.name else { return }
        runTracked(title: "Stop container", subtitle: name, arguments: ["docker", "stop", "--container", name])
    }

    private func filterDocker(_ containers: [DockerContainer]) -> [DockerContainer] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return containers }
        return containers.filter { container in
            [container.name, container.image, container.status, container.ports]
                .compactMap { $0?.lowercased() }
                .contains { $0.contains(query) }
        }
    }

    private func runTracked(title: String, subtitle: String, script: String? = nil, arguments: [String]) {
        let id = pushAction(title: title, subtitle: subtitle, state: .running)
        Task {
            do {
                let result = try await runPython(script: script ?? coordinatorScript, arguments: arguments)
                if result.status == 0 {
                    updateAction(id: id, state: .completed, detail: result.output)
                    await loadInventory()
                } else {
                    updateAction(id: id, state: .failed, detail: result.error.isEmpty ? result.output : result.error)
                }
            } catch {
                updateAction(id: id, state: .failed, detail: error.localizedDescription)
            }
        }
    }

    @discardableResult
    private func pushAction(title: String, subtitle: String, state: ActionItem.State, detail: String? = nil) -> ActionItem.ID {
        let item = ActionItem(title: title, subtitle: subtitle, state: state, detail: detail)
        actionItems.insert(item, at: 0)
        actionItems = Array(actionItems.prefix(20))
        return item.id
    }

    private func updateAction(id: ActionItem.ID, state: ActionItem.State, detail: String?) {
        guard let index = actionItems.firstIndex(where: { $0.id == id }) else { return }
        actionItems[index].state = state
        actionItems[index].detail = detail
    }

    private func ensureSuccess(_ result: CommandResult) throws {
        guard result.status == 0 else {
            throw RuntimeError(result.error.isEmpty ? result.output : result.error)
        }
    }
}

struct StartServerDraft {
    var agent = NSUserName()
    var project = FileManager.default.currentDirectoryPath
    var name = "web"
    var cwd = FileManager.default.currentDirectoryPath
    var command = "npm run dev -- --host 127.0.0.1 --port {port}"
    var range = "3000-3999"
    var healthURL = "http://127.0.0.1:{port}/"
}

struct RuntimeError: LocalizedError {
    var message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

func runPython(script: String, arguments: [String]) async throws -> CommandResult {
    try await Task.detached(priority: .userInitiated) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", script] + arguments

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        process.waitUntilExit()

        let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let error = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return CommandResult(output: output, error: error, status: process.terminationStatus)
    }.value
}
